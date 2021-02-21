Find vulnerabilities in dependencies of bob projects

-> Download the NVD database
-> Create some sort of search index
-> Update the DB every day with the new additions
-> Find CVE entries based on dependency coordinates
   -> These can be sort of generated from CPEs
   
The NVD database has some API documentation for downloading stuff:
https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CVE%20Retrieval.pdf

There is a maven plugin that does this already called DependencyCheck.
There is a 'How does it work?' page that describes roughly the same idea:
https://github.com/jeremylong/DependencyCheck/wiki/How-does-it-work%3F

Ideas for stuff
-> I could use the Lucene trick just like the DependencyCheck tool
-> Maybe something more custom using MapDB
-> NVD CVE entries can be easily stored on disk in a ~/.bobcvesearch/... dir
-> 

repo coordinate: org.mortbay.jetty:jetty:6.1.20
becomes cpe:     cpe:/a:mortbay:jetty:6.1.20