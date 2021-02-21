
[![Build Status](https://travis-ci.org/codemonstur/bobcvesearch.svg?branch=master)](https://travis-ci.org/codemonstur/bobcvesearch)
[![GitHub Release](https://img.shields.io/github/release/codemonstur/bobcvesearch.svg)](https://github.com/codemonstur/bobcvesearch/releases) 
[![MIT Licence](https://badges.frapsoft.com/os/mit/mit.svg?v=103)](https://opensource.org/licenses/mit-license.php)

# CVE search plugin for bob

A plugin for bob that checks for matching Common Vulnerability and Exposures for the dependencies in a project.

The code basically doesn't exist yet.

## Features

Current:

- none :(
  
Future:

- Report on CVEs matching dependencies
- Allow for suppression of findings
- Check if suppressions still match a dependency
- Fail build if results found
- Fail build if suppressions don't match any dependency
- Configure location of suppresion file
- Update DB if out of date
- Configure age of CVE DB
- Update DB only for mutations since last update

## Implementation

There doesn't appear to be a good way to turn a GAV (GroupId / ArtifactId / Version) coordinate into a CPE ([Common Platform Enumeration](https://nvd.nist.gov/products/cpe)).

This means that in order to find CVEs that match our dependencies we need to get creative. 
Basically we download the entire [CVE database](https://cve.mitre.org/data/downloads/index.html) and put the results into a [search index](https://lucene.apache.org/). Turns out I need to download the [NVD](https://nvd.nist.gov/vuln/data-feeds) database instead.
We then take the GAV, generate what might be a CPE, and uses everything we have to do one or more searches on our index.

Finally, we remove everything that has been explicitly suppressed in a config file.

## Usage

For now the plugin implements a command.
Which means that you can't call this functionality directly from the command line.

I'm thinking of adding some form of security task that can do multiple tasks:
- Check for newer versions of all the dependencies
- Check for CVEs connected to the dependencies
- Check for newer versions of all the frontend libraries
- Check for CVEs connected to frontend libraries
- Run static checkers (perhaps Sonar, Checkstyle, Findbugs, PMD, whatever else)

In order to make this work bob will need to have a generic security task where plugins can add things into.
The frontend checks for example will need to be implemented in HtmlCompiler.
While the dependency checks need to be implemented here.

## Known issues

1. Haven't written any code yet
2. Might generate lots of false positives
3. How to download CVE database updates?
4. How do I detect GAV like info from other dependency types?
5. The mitre CVE list doesn't contain CPEs and may be hard to match

## GAV to CPE

Example GAV:
```
<!-- https://mvnrepository.com/artifact/io.undertow/undertow-core -->
<dependency>
    <groupId>io.undertow</groupId>
    <artifactId>undertow-core</artifactId>
    <version>2.2.4.Final</version>
</dependency>
```
Potential CPEs from GAV info:
```
cpe:2.3:a:{groupId}:{artifactId}:*:*:*:*:*:*:*:*
cpe:2.3:a:{groupId}:{artifactId}:{version}:*:*:*:*:*:*:*
cpe:2.3:a:*:{groupId}:*:*:*:*:*:*:*:*
cpe:2.3:a:*:{groupId}:{version}:*:*:*:*:*:*:*
cpe:2.3:a:*:{artifactId}:*:*:*:*:*:*:*:*
cpe:2.3:a:*:{artifactId}:{version}:*:*:*:*:*:*:*
```
Example CPEs known in the wild:
```
cpe:2.3:a:redhat:undertow:2.0.0:sp1:*:*:*:*:*:*
cpe:2.3:a:junit:junit4:4.7:*:*:*:*:*:*:*
```
