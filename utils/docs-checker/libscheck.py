import requests
import os
import sys


def create_dir():
    try:
        os.makedirs("cached-docs")
    except FileExistsError:
        pass


def get_string(url):
    """
    Returns content from url in string format
    """
    try:
        h = requests.get(url, allow_redirects=True)
        return h.content.decode("utf-8")
    except UnicodeDecodeError:
        print("cant decode website content")
        return None


def write_to_path(file_path, string):
    file = open(file_path, "w")
    file.write(string)
    file.close()


def handle_urls(urls_file_path):
    create_dir()
    changed = 0
    urls = open(urls_file_path, "r")
    for url in urls:
        url = url.strip("\n/ ")
        if len(url) < 1 or url[0] == '#':
            continue
        file_name = os.path.basename(url)
        if file_name == "":
            continue
        print("handling \u001b[36m%-40s" % (file_name + "\u001b[0m..."),
              end=" ")
        url_content = get_string(url)
        if url_content is None or url_content == "404: Not Found":
            return 1
        try:
            file = open("./cached-docs/" + file_name, "r")
        except FileNotFoundError:
            write_to_path("./cached-docs/" + file_name, url_content)
            print("\u001b[34m[ NEW ]\u001b[0m")
            continue
        file_string = file.read()
        if file_string != url_content:
            print("\u001b[31m[ CHANGED ]\u001b[0m")
            print("Running diff between cached file and new file...")
            changed = 1
            file.close()

            write_to_path("./cached-docs/" + file_name + "_new", url_content)
            os.system(
                "diff ./cached-docs/%s ./cached-docs/%s_new"
                % (file_name, file_name))
            os.remove("./cached-docs/" + file_name + "_new")
            write_to_path("./cached-docs/" + file_name, url_content)
        else:
            print("\u001b[32m[ OK ]\u001b[0m")
            file.close()
    return changed


if __name__ == '__main__':
    sys.exit(handle_urls("utils/docs-checker/docs-urls.txt"))
