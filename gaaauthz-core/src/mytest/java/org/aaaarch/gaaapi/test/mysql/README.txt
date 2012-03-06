MySQL Package (Installation and Run)

Installation
Download MySQL Community Server from the website http://www.mysql.com/
Under windows, the *Windows Essentials (x86) works well (.exe)
You can install MySql easily, during the configuration you will be ask for a root password,
the default password use in XACMLRepository project is *toor*

Configuration
Using MySQL Command Line Client (from Start=>programms=>MySql), enter the password (toor).
You have to create the database XACMLRepository using the command:
*create database XACMLRepository;*

RUN AND MAIN
You can launch the main file, first you will have to create the table repository, and then
you will be able to add policy files and query the database using the PolicyId.

Thierry DENYS