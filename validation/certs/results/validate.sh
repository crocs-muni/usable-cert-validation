#!/bin/bash

# directory with all certs
CERTS_DIR=$1
# directory with TLS clients
CLIENTS_DIR=$2
# directory with all servers (main, CRL, OCSP)
SERVERS_DIR=$3
# chain name
CHAIN_NAME=$4
# validation output dir
OUT_DIR=$5
# port to run main server on
PORT_CTR_FILE=$6

# file to output the results into
OUT_FILE="${OUT_DIR}/${CHAIN_NAME}".yml
# validation config file
VCONFIG_FILE="${CERTS_DIR}/scripts/chains/${CHAIN_NAME}"/vconfig.yml
# directory with built chain
CHAIN_BUILD_DIR="${CERTS_DIR}/build/${CHAIN_NAME}"
# default root cert file
ROOT_CERT_FILE="${CERTS_DIR}/build/root/root.pem"
# default cert chain name
CHAIN_FILE="${CHAIN_BUILD_DIR}/chain.pem"
# default private key name
KEY_FILE="${CHAIN_BUILD_DIR}/key.pem"

# run servers on localhost
HOST=localhost


main() {
    if [ ! -f "${PORT_CTR_FILE}" ]
    then
      echo "50000" > ${PORT_CTR_FILE}
    fi

    MAIN_PORT=$(cat "${PORT_CTR_FILE}")
    increment_port
    
    PID=0
    run_servers
    sleep 0.3

    OUT="{}"
    # Loop through all clients, validating the chain with each
    for CLIENT_DIR in ${CLIENTS_DIR}/*
    do
        # Name of the client (library)
        CLIENT_NAME=$(basename "${CLIENT_DIR}")
        # YAML client config for the chain
        CLIENT_CONFIG=$(cat "${VCONFIG_FILE}" | shyaml -y get-value "verify.${CLIENT_NAME}" null)

        # Run this client only if it has a config
        if [ "${CLIENT_CONFIG}" != \'null\' ]
        then
        	# Look up the trust anchor (root CA) for this chain
        	TRUST_ANCHOR=$(echo "${CLIENT_CONFIG}" | shyaml get-value options.trust_anchor "${ROOT_CERT_FILE}")
        	if [ "${TRUST_ANCHOR}" != "${ROOT_CERT_FILE}" ]
        	then
        		TRUST_ANCHOR="${CHAIN_BUILD_DIR}/${TRUST_ANCHOR}"
        	fi

            # run the client and save its error message
            ERROR_MESSAGE="$("${CLIENT_NAME}"_validate 2>&1)"
            echo ${ERROR_MESSAGE}

            # Save the error message into the results with key being the client name
            OUT=$(echo ${OUT} | jq --arg m "${ERROR_MESSAGE}" \
                                   --arg l "${CLIENT_NAME}" \
                                   --arg c "${CHAIN_NAME}" \
                                   '.[$c][$l] = $m')
        fi
    done

    # close the servers
    kill ${PID}

    # output the results into a YAML file
    echo ${OUT} | yq --yaml-output '.' - > ${OUT_FILE}
}


run_servers() {
    SERVER_CONFIG=$(cat "${VCONFIG_FILE}" | shyaml -y get-value servers)
    WHICH_MAIN=$(echo "${SERVER_CONFIG}" | shyaml get-value main.which "botan")

    if [ "${WHICH_MAIN}" == "python" ]
    then
        python "${SERVERS_DIR}"/server.py --chain_file "${CHAIN_FILE}" \
                                        --key_file "${KEY_FILE}" \
                                        --host "${HOST}" \
                                        --port "${MAIN_PORT}" &
                                        #> /dev/null 2>&1 &
    else 
        botan tls_server "${CHAIN_FILE}" \
                         "${KEY_FILE}" \
                         --port="${MAIN_PORT}" &
                         #> /dev/null 2>&1 &
    fi
    PID=$!
}


openssl_validate() {
    FLAGS=$(echo "${CLIENT_CONFIG}" | shyaml get-value options.flags "")
    MAX_DEPTH=$(echo "${CLIENT_CONFIG}" | shyaml get-value options.max_depth -1)
    EMAIL=$(echo "${CLIENT_CONFIG}" | shyaml get-value options.email "")
    IP=$(echo "${CLIENT_CONFIG}" | shyaml get-value options.ip "")
    POLICY=$(echo "${CLIENT_CONFIG}" | shyaml get-value options.policy "")
    PURPOSE=$(echo "${CLIENT_CONFIG}" | shyaml get-value options.purpose "")
    TRUST=$(echo "${CLIENT_CONFIG}" | shyaml get-value options.trust "")
    ${CLIENT_DIR}/build/client --host "${HOST}" \
                               --port "${MAIN_PORT}" \
                               --trust_anchor "${TRUST_ANCHOR}" \
                               --max_depth "${MAX_DEPTH}" \
                               --email "${EMAIL}" \
                               --ip "${IP}" \
                               --policy "${POLICY}" \
                               --purpose "${PURPOSE}" \
                               --trust "${TRUST}" \
                               "${FLAGS}"
}


gnutls_validate() {
    ${CLIENT_DIR}/build/client --host "${HOST}" \
                               --port "${MAIN_PORT}" \
                               --trust_anchor "${TRUST_ANCHOR}"
}


botan_validate() {  
    ${CLIENT_DIR}/build/client --host "${HOST}" \
                               --port "${MAIN_PORT}" \
                               --trust_anchor "${TRUST_ANCHOR}"
}


mbedtls_validate() {
    ${CLIENT_DIR}/build/client --host "${HOST}" \
                               --port "${MAIN_PORT}" \
                               --trust_anchor "${TRUST_ANCHOR}"
}


openjdk_validate() {
    java -classpath ${CLIENT_DIR}/build/ Client --host "${HOST}" \
                                                --port "${MAIN_PORT}" \
                                                --trust_anchor "${TRUST_ANCHOR}"
}

increment_port() {
    NEXT_PORT=$(cat "${PORT_CTR_FILE}")
    ((NEXT_PORT++))
    if [ "${NEXT_PORT}" -ge "60000" ]
    then
        NEXT_PORT=50000
    fi
    echo -n "${NEXT_PORT}" > ${PORT_CTR_FILE}
}


main "$@"