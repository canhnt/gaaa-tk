Exist Package (Installation, Modifications and Run)

Installation
Download eXist database from http://exist.sourceforge.net/
For windows download .exe file
You will be ask for the JDK path, it should be a path like:
C:\Sun\SDK\jdk
The installation is very easy, 
you will have to enter a password, you can use *toor* (default password for project)

Configuration
For the eXist database, in the file config.xml (eXist folder installation)
change the indexer tag 
 
   	<indexer caseSensitive="yes" index-depth="5"
        preserve-whitespace-mixed-content="no" stemming="no"
        suppress-whitespace="both"
        tokenizer="org.exist.storage.analysis.SimpleTokenizer"
        track-term-freq="yes" validation="no">
        
And put (like that), the validation  => "no" (by default it's "auto")

Else, you will have a problem with your XML policies (error validation) and
these files won't be added in your database

Start eXist Database Startup from Start>Programms>eXist XML Database

RUN AND MAIN
You can launch the main file, first you will have to create the collection, and then
you will be able to add policy files and query the database using the PolicyId.

Note:
If you have an apache server, you can manage your database from the web, using eXist Local Homepage:
Start>Programms>eXist XML Database

Thierry DENYS