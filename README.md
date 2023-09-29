# ISA Project 2022/23 - RSS/Atom FeedReader

Project for the BUT FIT course ISA, year 22/23. RSS 2.0 / Atom CLI reader.

Author: Tadeas Kozub _xkozub06_

Contact: xkozub06@fit.vutbr.cz

### Installation

Run the Makefile to compile the project:

`$ make`

This will create a file named `feedreader`.

**!WARNING!** Error `/usr/bin/ld: cannot find -lstdc++` during compilation means
that you do not have static libraries available. In this case, use the _nostatic_ target
as follows:

`$ make nostatic`

The program should now compile correctly and, as mentioned in the previous paragraph, create an executable file named `feedreader`.

To run the tests, use the following command:

`$ make test`

To clean the directory, use:

`$ make clean`

## Usage

Display the content from the specified feeds and any additional information using this command:

`$ ./feedreader <URL | -f <feedfile>> [-c <certfile>] [-C <certaddr>] [-T] [-a] [-u] [-d]`

Both HTTP and HTTPS connections are supported for feed sources. The feedfile format is a standard text file containing URL links, each on its own line, and optionally also containing comments starting with the `#` symbol on their own line. The file is a standard UNIX file with `\n` line endings and one `\n` at the end of the file.

You can provide the program with a certificate file, a directory with certificates, or both. If you do not use either of these options, the system's default certificates will be used.

## Usage Examples

```
$ ./feedreader -f ~/feed_file.txt -a
# Display feeds from URLs specified in the feedfile and for each article
# also display author information if available

$ ./feedreader https://what-if.xkcd.com/feed.atom -c ~/certs/my_cert_file.crt
# Display the feed from xkcd.com and use the specified certificate from the ~/certs/ directory
# for identity verification

$ ./feedreader https://what-if.xkcd.com/feed.atom -Tau >> feed_output.txt
# Display all supported information (if available)
# and redirect the program's output to the specified file
```
