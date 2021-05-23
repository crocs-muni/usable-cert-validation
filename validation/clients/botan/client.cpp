#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <cstring>

#include <botan/tls_client.h>
#include <botan/certstor.h>
#include <botan/auto_rng.h>
#include <botan/x509path.h>
#include <botan/ocsp.h>
#include <botan/tls_exceptn.h>

#include <boost/program_options.hpp>

class ClientCB : public Botan::TLS::Callbacks {
private:
    void tls_emit_data(const uint8_t data[], size_t size) override {
        send(sockfd, data, size, 0);
    }

    void tls_record_received(uint64_t seq_no, const uint8_t data[], size_t size) override {
        (void)seq_no;
        (void)data;
        (void)size;
    }

    void tls_alert(Botan::TLS::Alert alert) override {
        (void)alert;
    }

    bool tls_session_established(const Botan::TLS::Session &session) override {
        (void)session;
        return false;
    }
    void tls_verify_cert_chain(
        const std::vector<Botan::X509_Certificate>& cert_chain,
        const std::vector<std::shared_ptr<const Botan::OCSP::Response>>& ocsp_responses,
        const std::vector<Botan::Certificate_Store*>& trusted_roots,
        Botan::Usage_Type usage,
        const std::string& hostname,
        const Botan::TLS::Policy& policy) override
    {
        if(cert_chain.empty()) {
            throw Botan::Invalid_Argument("Certificate chain was empty");
        }

        Botan::Path_Validation_Restrictions restrictions(
            policy.require_cert_revocation_info(),
            policy.minimum_signature_strength());

        auto ocsp_timeout = std::chrono::milliseconds(1000);

        Botan::Path_Validation_Result result = Botan::x509_path_validate(
            cert_chain,
            restrictions,
            trusted_roots,
            hostname,
            usage,
            std::chrono::system_clock::now(),
            ocsp_timeout,
            ocsp_responses);

        std::cout << result.result_string();
    }

public:
    int sockfd = -1;

    int tcp_connect(const std::string &host, const std::string &port) {
        /* Hints that we send to server with our preferences */
        struct addrinfo hints = {
            .ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV,
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = IPPROTO_TCP,
            .ai_addrlen = 0,
            .ai_addr = nullptr,
            .ai_canonname = nullptr,
            .ai_next = nullptr
        };

        /* We allow both IPv4 and IPv6 */
        hints.ai_family = AF_UNSPEC;
        /* We want a stream socket, not a datagram one */
        hints.ai_socktype = SOCK_STREAM;
        /* We know the numeric port number beforehand */
        hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
        /* We want to use TCP */
        hints.ai_protocol = IPPROTO_TCP;

        struct addrinfo *result = nullptr;

        /* Try to get the server addrinfo list */
        if (getaddrinfo(host.c_str(), port.c_str(), &hints, &result) != 0 || result == nullptr) {
            return -1;
        }

        /* Try each address from the server list until successful */
        struct addrinfo *rr;
        for (rr = result; rr != nullptr; rr = rr->ai_next) {
            this->sockfd = socket(rr->ai_family, rr->ai_socktype, rr->ai_protocol);
            if (this->sockfd == -1)
                continue;
            if (connect(this->sockfd, rr->ai_addr, rr->ai_addrlen) != -1)
                break;
            close(this->sockfd);
        }

        /* We don't need the server info anymore */
        freeaddrinfo(result);

        /* Fail if we didn't manage to connect to any server address */
        if (rr == nullptr) {
            return -1;
        }
        return this->sockfd;
    }
};

class Client_Credentials : public Botan::Credentials_Manager {
public:
    explicit Client_Credentials(const std::string &ca) {
        // load and set the trust anchor
        auto cacert_ptr = std::make_shared<Botan::X509_Certificate>(ca);
        anchor_ptr = std::make_shared<Botan::Certificate_Store_In_Memory>();
        anchor_ptr->add_certificate(cacert_ptr);
    }

    std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(
            const std::string &type,
            const std::string &context) override {
        // return list of trusted stores
        (void)type;
        (void)context;
        std::vector<Botan::Certificate_Store *> store_list;
        store_list.push_back(anchor_ptr.get());
        return store_list;
    }

    std::vector<Botan::X509_Certificate> cert_chain(
            const std::vector<std::string> &cert_key_types,
            const std::string &type,
            const std::string &context) override {
        // we return an empty list of certificates, since we are not doing client auth
        (void)cert_key_types;
        (void)type;
        (void)context;
        return std::vector<Botan::X509_Certificate>();
    }

    Botan::Private_Key *private_key_for(const Botan::X509_Certificate &cert,
                                        const std::string &type,
                                        const std::string &context) override {
        // we return nullptr since we are not doing client auth
        (void)cert;
        (void)type;
        (void)context;
        return nullptr;
    }

private:
    // trusted store
    std::shared_ptr<Botan::Certificate_Store_In_Memory> anchor_ptr;
};

int main(int argc, char **argv) {
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
            ("host", boost::program_options::value<std::string>(), "Hostname")
            ("port", boost::program_options::value<std::string>(), "Port")
            ("trust_anchor", boost::program_options::value<std::string>(), "Trusted CA")
            ("check_crl", boost::program_options::value<bool>(), "Check CRLs")
            ("check_ocsp", boost::program_options::value<bool>(), "Check OCSP")
            ("check_ocsp_staple", boost::program_options::value<bool>(), "Check OCSP staple")
    ;
    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
    boost::program_options::notify(vm);

    std::string host = vm["host"].as<std::string>();
    std::string port = vm["port"].as<std::string>();
    std::string trust_anchor = vm["trust_anchor"].as<std::string>();

    // prepare rng
    Botan::AutoSeeded_RNG rng;

    // prepare all the parameters
    Botan::TLS::Session_Manager_In_Memory session_mgr(rng);
    Client_Credentials creds(trust_anchor);

    class Policy : public Botan::TLS::Strict_Policy
    {
    public:
        bool require_cert_revocation_info() const override {
            return false;
        }
    };

    Policy policy;

    ClientCB clientCB;

    clientCB.tcp_connect(host, port);

    // open the tls connection
    Botan::TLS::Client client(clientCB,
                              session_mgr,
                              creds,
                              policy,
                              rng,
                              Botan::TLS::Server_Information(host, port),
                              Botan::TLS::Protocol_Version::TLS_V12);

    // handshake
    while (!client.is_closed() && !client.is_active()) {
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(clientCB.sockfd, &readfds);
        struct timeval timeout = { 1, 0 };
        select(clientCB.sockfd + 1, &readfds, nullptr, nullptr, &timeout);

        if(FD_ISSET(clientCB.sockfd, &readfds)) {
            uint8_t buf[4096] = {0};   
            ssize_t got = read(clientCB.sockfd, buf, 4096);
            
            if (got > 1) {
                try {
                    client.received_data(buf, got);
                } catch (Botan::Decoding_Error &e) {
                    std::cout << "Botan::Decoding_error: " << e.what();
                } catch (Botan::Encoding_Error &e) {
                    std::cout << "Botan::Encoding_Error: " << e.what();
                } catch (Botan::Invalid_Algorithm_Name &e) {
                    std::cout << "Botan::Invalid_Algorithm_Name: " << e.what();
                } catch (Botan::Invalid_Argument &e) {
                    std::cout << "Botan::Invalid_argument: " << e.what();
                } catch (Botan::TLS::TLS_Exception &e) {
                    std::cout << "Botan::TLS_Exception: " << e.what();
                } catch (std::exception &e) {
                    std::cout << "Exception: " << e.what();
                }
            }
        }
    }
    if (!client.is_closed()) {
        client.close();
    }
    close(clientCB.sockfd);
}
