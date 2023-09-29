/*
* BUT FIT Brno
* Subject: ISA 2022/23
* Project: RSS2.0/Atom FeedReader
*
* Author: Tadeas Kozub (xkozub06)
* Date: 2022/10/03
*
*/


#include <filesystem>  
#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

#include <stdio.h> 
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
  
using namespace std;

#define HTTP_PARSING_ERROR -2
#define CERT_CHECK_ERROR -3

#define READ_BUFFER_SIZE 4096

bool SHOW_DEBUG = false;

void DEBUG_MSG(string text) {
    if (SHOW_DEBUG) {
        fprintf(stderr, text.c_str());
        fprintf(stderr, "\n");
    }
}

void ERROR_MSG(string text) {
    fprintf(stderr, "Error: %s\n", text.c_str());
}

int show_help(){
    printf("Usage: feedreader <URL | -f <feedfile>> [-c <certfile>] [-C <certaddr>] [-T] [-a] [-u] [-d]\n");
    printf("\n");

    printf("Required:\n");
    printf("-f <feedfile> || <URL>  add a feedfile location to read the source URL from OR a URL of the source.\n");
    printf("\n");
    printf("Optional:\n");
    printf("-c <certfile>  add a certificate file location.\n");
    printf("-C <certaddr>  add a cerificate directory location.\n");
    printf("-T             show time information of each post.\n"); 
    printf("-a             show author's name / email address.\n"); 
    printf("-u             show the url of the original post.\n"); 
    printf("-d             show debug messages.\n");
    return 0;
}

// Teran, E. (2008) https://stackoverflow.com/a/217605
// trim from start (in place)
static inline void ltrim(std::string &s) {
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
}

// Teran, E. (2008) https://stackoverflow.com/a/217605
// trim from end (in place)
static inline void rtrim(std::string &s) {
    s.erase(std::find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), s.end());
}

// Teran, E. (2008) https://stackoverflow.com/a/217605
// trim from both ends (in place)
static inline void trim(std::string &s) {
    ltrim(s);
    rtrim(s);
}

class URL {
    public:
        bool https = false;
        string authority = "";
        string path = "";
        string port = "";
};


class userArgs {
    public:
        vector<URL> URLlist;
        string feedFilePath = "";
        string certFilePath = "";
        string certAddrPath = "";
        bool showTime = false;
        bool showAuthor = false;
        bool showSourceUrl = false;

    void parseSingleURL(string extraArg) {
        regex isURL("https?://[a-zA-Z0-9.-]+(:[0-9]+)?/[~a-zA-Z0-9/? .=&-_]*");
        if(regex_match (extraArg, isURL)) {
            DEBUG_MSG("Received a valid URL format.");
            this->URLlist.push_back(extractUrl(extraArg));
        }
        else {
            ERROR_MSG("Invalid URL format: " + extraArg);
        }
    }

    // HugoTeixeira (2018) https://stackoverflow.com/a/51572325
    void parseFeedfile() {
        ifstream file(this->feedFilePath);
        vector<URL> tempUrlVector;
        if (file.is_open()) {
            std::string line;
            regex isURL("https?://[a-zA-Z0-9.-]+(:[0-9]+)?/[~a-zA-Z0-9/? .=&-_]*");
            while (std::getline(file, line)) {
                trim(line);
                if(regex_match(line, isURL)) {
                    tempUrlVector.push_back(extractUrl(line));
                }
            }
            file.close();
            this->URLlist = tempUrlVector;
        }
    }

    URL extractUrl(string validURL) {
        URL url;
        regex isHttps("^https.*");
        if (regex_match (validURL, isHttps)) {
            url.https = true;
        }
        else {
            url.https = false;
        }
        extractAuthorityAndPath(validURL, url);
        return url;

    }
    
    // PherricOxide (2012) & llnspectable (2021) https://stackoverflow.com/a/12774387
    void checkFileExists (string name) {
        if (!(access( name.c_str(), F_OK ) != -1)) {
            ERROR_MSG("Can't access provided file" + name);
            exit(1);
        }
        else {
            DEBUG_MSG("Checked certificate file " + name);
        }
    }

    void extractAuthorityAndPath(string validURL, URL &url) {
        char authority[256] = {0};
        char path[256] = {0};
        char port[256] = {0};
        if (validURL.length() > 256) {
            ERROR_MSG("Fatal - URL is too long.");
            url.authority = "";
            url.path = "";
            return;
        }
        
        bool firstSlashMatched, secondSlashMatched, readingPort, thirdSlashMatched = false;
        size_t current_auth_len = 0;
        size_t current_path_len = 0;
        size_t current_port_len = 0;
        for (size_t i = 0; i < validURL.length(); i++)
        {   
            if (thirdSlashMatched) {
                path[current_path_len++] = validURL[i];
            }
            else if (readingPort && validURL[i] == '/') {
                thirdSlashMatched = true;
                readingPort = false;
                path[current_path_len++] = validURL[i];
            }
            else if (readingPort) {
                port[current_port_len++] = validURL[i];
            }
            else if (secondSlashMatched && validURL[i] == '/') {
                thirdSlashMatched = true;
                path[current_path_len++] = validURL[i];
            }
            else if (secondSlashMatched && validURL[i] == ':') {
                readingPort = true;
            }
            else if (secondSlashMatched) {
                authority[current_auth_len++] = validURL[i];
            }
            else if(firstSlashMatched && validURL[i] == '/') {
                secondSlashMatched = true;
            }
            else if (validURL[i] == '/') {
                firstSlashMatched = true;
            }
        }
        url.authority = authority;
        url.path = path;
        url.port = port;

        DEBUG_MSG("authority: " + (string)authority);
        DEBUG_MSG("port: " + (string)port);
        DEBUG_MSG("path: " + (string)path);
    }

    int parseArguments(int argc, char *argv[]) {
        if (argc == 1 || argc < 0) {
            show_help();
            exit(1);
        }
        int opt;
        bool feedfile_available = false;
        
        // SrjSunny (2018) https://www.geeksforgeeks.org/getopt-function-in-c-to-parse-command-line-arguments/
        // put ':' in the starting of the
        // string so that program can 
        // distinguish between '?' and ':' 
        while((opt = getopt_long(argc, argv, ":hf:c:C:Taud", NULL, NULL)) != -1) 
        { 
            switch(opt) 
            { 
                case 'h':
                    show_help();
                    exit(0); 
                case 'f': 
                    feedfile_available = true;
                    this->feedFilePath = optarg;
                    break; 
                case 'c': 
                    checkFileExists(optarg);
                    this->certFilePath = optarg;
                    break; 
                case 'C':
                    this->certAddrPath = optarg; 
                    break;
                case 'T':
                    this->showTime = true;
                    break;
                case 'a':
                    this->showAuthor = true;
                    break;
                case 'u':
                    this->showSourceUrl = true;
                    break;
                case 'd':
                    SHOW_DEBUG = true;
                    break;
                case ':': 
                    ERROR_MSG("option needs a value\n"); 
                    // handle this further? Return an error?
                    break; 
                case '?': 
                    fprintf(stderr, "unknown option: %c\n", optopt);
                    show_help();
                    exit(1);
            } 
        } 
      
        // optind is for the extra arguments which are not parsed
        int extra_count = 0;
        string extraArg = "";
        for(; optind < argc; optind++){     
            if (extra_count > 0 || feedfile_available){
                ERROR_MSG("Too many sources.");
                show_help();
                exit(1);
            }
            DEBUG_MSG("extra arguments: " + (string)argv[optind]); 
            extraArg = argv[optind];

            extra_count += 1;
        }
        if (feedfile_available){
            checkFileExists(this->feedFilePath);
            parseFeedfile();
        }
        else {
            parseSingleURL(extraArg);
        }
        return 0;        
    }
};


class feedFetcher {
    public:
        URL url;
        string HTTPresponse = "";

    void cleanupFetcher() {
        this->url = URL();
        this->HTTPresponse = "";
    }

    int checkValidResponse(string rawResponse) {
        DEBUG_MSG("Checking validity of HTTP Response...");
        if (rawResponse == "") {
            ERROR_MSG("Received empty HTTP response");
            return HTTP_PARSING_ERROR;
        }
        // loop through strings each line
        istringstream stringStream(rawResponse);
        bool xmlFound = false;
        for (string line; getline(stringStream, line); ) {
            trim(line);
            
            if (line.rfind("<?xml", 0) == 0) {
                // XML found
                return 0;
                }
        }
        ERROR_MSG("No XML found in HTTP response");
        return HTTP_PARSING_ERROR;
    }

    string parseHttpResponse(string rawResponse) {
        DEBUG_MSG("Parsing HTTP Response...");
        string xml = "";
        istringstream stringStream(rawResponse);
        for (string line; getline(stringStream, line); ) {
            trim(line);
            
            if (line.rfind("<?xml", 0) == 0) {
                xml = line + "\n";
                while (getline(stringStream, line)) {
                    xml += line += "\n";
                }
            }
        }
        cleanupFetcher();
        return xml;
    }
            
    int fetchPost(URL url, userArgs args) {
        this->url = url;

        DEBUG_MSG("fetching post from " + url.authority + "\n");


        // initialization of SSL library
        SSL_library_init();
	    SSL_load_error_strings();

        BIO *bio = NULL;
        SSL_CTX *ctx = NULL;
        if (url.https) {
            ctx = SSL_CTX_new(SSLv23_client_method());

            int verify = 0;
            if (args.certFilePath != "" && args.certAddrPath != "") {
                verify = SSL_CTX_load_verify_locations(ctx, args.certFilePath.c_str(), args.certAddrPath.c_str());
            }
            else if (args.certFilePath != "") {
                verify = SSL_CTX_load_verify_locations(ctx, args.certFilePath.c_str(), NULL);
            }
            else if (args.certAddrPath != "") {
                verify = SSL_CTX_load_verify_locations(ctx, NULL, args.certAddrPath.c_str());
            }
            else {
                verify = SSL_CTX_set_default_verify_paths(ctx);
            }
            if (!verify) {
                ERROR_MSG("Verification of certificate paths failed.");
                return CERT_CHECK_ERROR;
            }
            DEBUG_MSG("Certificate verification complete");

            bio = BIO_new_ssl_connect(ctx);
            if (!bio) {
                ERROR_MSG("Connection to " + url.authority + " failed.");
                exit(1);
            }
            DEBUG_MSG("New SSL Connect successful");

            SSL *ssl = NULL;
            BIO_get_ssl(bio, &ssl);
            string hostname = url.authority;
            if (url.port == ""){
                hostname.append(":443");
            }
            else {
                hostname.append(":" + url.port);
            }
            SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
            BIO_set_conn_hostname(bio, hostname.c_str());
            SSL_set_tlsext_host_name(ssl, url.authority.c_str());
            if (BIO_do_connect(bio) <= 0) {
                ERROR_MSG("Connection to " + url.authority + " failed.");
                ERR_print_errors_fp(stderr);
                exit(1);
            }
            DEBUG_MSG("Connection to " + url.authority + " successful");

            if (ssl && SSL_get_verify_result(ssl) != X509_V_OK) {
                ERROR_MSG("Verification of certificates for " + url.authority + " failed.");
                return CERT_CHECK_ERROR;
            }
            DEBUG_MSG("X.509 certificate verification complete");
            
        }
        // handle http communication
        else {
            string hostname = url.authority;
            if (url.port == "") {
                hostname.append(":80");
            }
            else {
                hostname.append(":" + url.port);
            }
            bio = BIO_new_connect(hostname.c_str());
            if (!bio) {
                ERROR_MSG("Connection to " + url.authority + " failed.");
                exit(1);
            }
            DEBUG_MSG("HTTP connection successful");

            if (BIO_do_connect(bio) <= 0) {
                ERR_print_errors_fp(stderr);
                ERROR_MSG("Connection to " + url.authority + " failed.");
                exit(1);
            }
            DEBUG_MSG("Connection to " + url.authority + " successful");
        }
        
        string request(
                "GET " + url.path + " HTTP/1.0\r\n"
                "Host: " + url.authority + "\r\n"
                "Connection: Close\r\n"
                "User-Agent: Mozilla/5.0 Chrome/90.0.4480.84 Safari/537.36\r\n\r\n"
            );
        // attempting to write to BIO
        DEBUG_MSG("Sending request:\n" + request);
        DEBUG_MSG("Writing request to BIO...");
        BIO_puts(bio, request.c_str());

        char responseBuffer[READ_BUFFER_SIZE] = {0};

        // attempting to read the response from BIO
        DEBUG_MSG("Reading BIO...");
        string rawResponse = "";
        while (1) {
            memset(responseBuffer, '\0', sizeof(responseBuffer));
            int n = BIO_read(bio, responseBuffer, READ_BUFFER_SIZE - 1);
            if (n <= 0) {
                break;
            } /* 0 is end-of-stream, < 0 is an error */
            rawResponse.append(responseBuffer);

        }
        // final cleanup:
        if (bio){
            BIO_free_all(bio);
        }
        if (ctx){
            SSL_CTX_free(ctx);
        }
        HTTPresponse = rawResponse;
        return 0;
    }
};


class XMLParser {
    public:
    bool firstFeed = true;


    bool nodeType(xmlNode* cur_node, string type) {
        if (!strcmp((char*)cur_node->name, type.c_str())) {
            return true;
        }
        return false;
    }

    void parseAtom(xmlNode* rootNode, userArgs args) {
        xmlNode* cur_node = NULL;
        xmlNode* entry_node = NULL;
        xmlNode* author_node = NULL;

        // print the title of the entire feed
        for (cur_node = rootNode->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                if (nodeType(cur_node, "title")) {
                    if (firstFeed) {
                        firstFeed = false;
                    }
                    else {
                        printf("\n");
                    }
                    printf("*** %s ***\n", (char*)xmlNodeGetContent(cur_node));
                }
            }
        }
        // unfortunately, the xml tree doesn't keep the same order, so to keep it structured, we need to save every
        // string and put them together after
        bool firstEntry = true;
        string title = "";
        string link = "";
        string updated = "";
        string author = "";
        string name = "";
        string email = "";
        string prefix = "";
        if (args.showAuthor || args.showSourceUrl || args.showTime) {
            prefix = "\n";
        }
        for (cur_node = rootNode->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && nodeType(cur_node, "entry")) {
                for (entry_node = cur_node->children; entry_node; entry_node = entry_node->next) {
                    if (entry_node->type == XML_ELEMENT_NODE && nodeType(entry_node, "title")) {
                        title = (string)(char*)xmlNodeGetContent(entry_node) + "\n";
                    }
                    if (args.showSourceUrl && entry_node->type == XML_ELEMENT_NODE && nodeType(entry_node, "link")) {
                        link = "URL: " + (string)(char*)xmlGetProp(entry_node, (xmlChar*)"href") + "\n";
                    }
                    if (args.showTime && entry_node->type == XML_ELEMENT_NODE && nodeType(entry_node, "updated")) {
                        updated = "Aktualizace: " + (string)(char*)xmlNodeGetContent(entry_node) + "\n";
                    }
                    if (args.showAuthor && entry_node->type == XML_ELEMENT_NODE && nodeType(entry_node, "author")) {
                        for (author_node = entry_node->children; author_node; author_node = author_node->next) {
                            if (author_node->type == XML_ELEMENT_NODE && nodeType(author_node, "name")) {
                                name = (string)(char*)xmlNodeGetContent(author_node);
                            }
                            if (author_node->type == XML_ELEMENT_NODE && nodeType(author_node, "email")) {
                                email = (string)(char*)xmlNodeGetContent(author_node);
                            }
                        }
                    }
                }
                if (name == "" && email == "") {
                    author = "";
                }
                else {
                    author = "Autor: " + name + " " + email + "\n";
                }
                if (firstEntry) {
                    firstEntry = false;
                    string entry = title + link + updated + author;
                    printf("%s", entry.c_str());
                }
                else {
                    string entry = prefix + title + link + updated + author;
                    printf("%s", entry.c_str());
                }
            }
        }
    }

    void parseRSS2(xmlNode* rootNode, userArgs args) {
        xmlNode* cur_node = NULL;
        xmlNode* channel_node = NULL;
        xmlNode* item_node = NULL;

        // print the title of the entire feed
        for (cur_node = rootNode->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && nodeType(cur_node, "channel")) {
                for (channel_node = cur_node->children; channel_node; channel_node = channel_node->next) {
                    if (channel_node->type == XML_ELEMENT_NODE && nodeType(channel_node, "title")) {
                        if (firstFeed) {
                            firstFeed = false;
                        }
                        else {
                            printf("\n");   
                        }
                        printf("*** %s ***\n", (char*)xmlNodeGetContent(channel_node));
                    }
                }
            }
        }
        // unfortunately, the xml tree doesn't keep the same order, so to keep it structured, 
        // we need to save every string and put them together after the innermost loop
        bool firstEntry = true;
        string prefix = "";
        string title = "";
        string link = "";
        string updated = "";
        string author = "";
        if (args.showAuthor || args.showSourceUrl || args.showTime) {
            prefix = "\n";
        }
        for (cur_node = rootNode->children; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE && nodeType(cur_node, "channel")) {
                for (channel_node = cur_node->children; channel_node; channel_node = channel_node->next) {
                    if (channel_node->type == XML_ELEMENT_NODE && nodeType(channel_node, "item")) {
                        for (item_node = channel_node->children; item_node; item_node = item_node->next) {
                            if (item_node->type == XML_ELEMENT_NODE && nodeType(item_node, "title")) {
                                title = (string)(char*)xmlNodeGetContent(item_node) + "\n";
                            }
                            if (args.showSourceUrl && item_node->type == XML_ELEMENT_NODE && nodeType(item_node, "link")) {
                                link = "URL: " + (string)(char*)xmlNodeGetContent(item_node) + "\n";
                            }
                            if (args.showTime && item_node->type == XML_ELEMENT_NODE && nodeType(item_node, "pubDate")) {
                                updated = "Aktualizace: " + (string)(char*)xmlNodeGetContent(item_node) + "\n";
                            }
                            if (args.showAuthor && item_node->type == XML_ELEMENT_NODE && nodeType(item_node, "author")) {
                                author = "Autor: " + (string)(char*)xmlNodeGetContent(item_node) + "\n";
                            }
                            
                        }
                        if (firstEntry) {
                            firstEntry = false;
                            string entry = title + link + updated + author;
                            printf("%s", entry.c_str());
                        }
                        else {
                            string entry = prefix + title + link + updated + author;
                            printf("%s", entry.c_str());
                        }
                    }
                }
            }
        }
    }

    void parse(string xml, userArgs args) {
        xmlDoc *doc = NULL;
        xmlNode *root_element = NULL;

        LIBXML_TEST_VERSION

        // parse the file and get the DOM 
        doc = xmlReadDoc((xmlChar*)xml.c_str(), NULL, NULL, 0);

        if (doc == NULL) {
            ERROR_MSG("Could not parse XML\n");
            exit(1);
        }

        root_element = xmlDocGetRootElement(doc);

        if (root_element->type == XML_ELEMENT_NODE && nodeType(root_element, "feed")) {
                DEBUG_MSG("parsing Atom\n");
                parseAtom(root_element, args);
        }
        else if (root_element->type == XML_ELEMENT_NODE && nodeType(root_element, "rdf")) {
            ERROR_MSG("RSS1.0 not supported\n");
        }
        else if (root_element->type == XML_ELEMENT_NODE && nodeType(root_element, "rss")) {
            if (xmlStrEqual(xmlGetProp(root_element, (xmlChar*)"version"), (xmlChar*)"2.0")) {
                DEBUG_MSG("parsing RSS2.0\n");
                parseRSS2(root_element, args);
            }
            else {
                ERROR_MSG("Unknown RSS version\n");
            }
        }
        else {
            ERROR_MSG("Unknown XML format\n");
        }

        xmlFreeDoc(doc);
        xmlCleanupParser();
    }
};

int main(int argc, char *argv[]) 
{
    userArgs arguments;
    feedFetcher fetcher;
    XMLParser xml_parser;

    arguments.parseArguments(argc, argv);

    // loop over URLlist:
    for(size_t i = 0; i < arguments.URLlist.size(); i++) {
        if (fetcher.fetchPost(arguments.URLlist[i], arguments) == CERT_CHECK_ERROR) {
            fetcher.cleanupFetcher();
            continue;
        }
        if (fetcher.checkValidResponse(fetcher.HTTPresponse) == HTTP_PARSING_ERROR) {
            ERROR_MSG("Couldn't parse the feed for " + arguments.URLlist[i].authority);
            fetcher.cleanupFetcher();
            continue;
        }
        string xml = fetcher.parseHttpResponse(fetcher.HTTPresponse);
        xml_parser.parse(xml, arguments);
    }
    return 0;
}