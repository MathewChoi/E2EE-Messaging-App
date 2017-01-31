# E2EE-Messaging-App
Project Contributors
Mathew Choi and Ryan Riehl

Project Phases:
1. Setup your aws LAMP Ubuntu Server --- CURRENT PHASE
2. Setup a simple HTTPS Server
3. Encapsulation/Decapsulation
4. JWT and RESTful

Useful Links:
  Setting up an AWS Instance with LAMP and Git
    Good (though a bit old) tutorial:
    http://devoncmather.com/setting-aws-ec2-instance-lamp-git/
    Install the latest Ubuntu.
    Youtube Explanation:
    https://www.youtube.com/watch?v=wNr7YqjjzOY
    More resources:
    http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/get-set-up-for-amazon-ec2.html
    https://help.ubuntu.com/community/ApacheMySQLPHP
  
  RESTful and JWT
    RESTful architecture is platform and language independent but since there are quite a few Java people in this class, the link below  gives a good overview of API development in Java. Please feel free to share with everyone if you find any better and easier tutorial:
    http://www.codingpedia.org/ama/tutorial-rest-api-design-and-implementation-in-java-with-jersey-and-spring/
    As for JWT, you can't beat this intro:
    https://jwt.io/introduction/
    However, these authors have done a decent job:
    http://phpclicks.com/php-token-based-authentication/
    https://www.toptal.com/web/cookie-free-authentication-with-json-web-tokens-an-example-in-laravel-and-angularjs
    
  SSL Config
    The instructions below are intended for Apache. NGINX and Node are slightly different.
    Run SSL Lbas on your config and report your observations to class.
    You want your ssl config file to include these lines:
    LoadModule ssl_module modules/mod_ssl.so
    <IfModule mod_ssl.c>
    SSLEngine on
    SSLProtocol -all +TLSv1.2
    # "whenever TLSv1.3 comes along you'll need to update your OpenSSL and Apache and change 1.2 to the newer version"
    SSLHonorCipherOrder On
    SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-CBC-SHA384:ECDHE-RSA-AES256-CBC-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:!aNULL:!MD5:!DSS

    **************************************************
    Your httpd.conf config file would have
    <VirtualHost *:443>
    ServerName NAME.name
    ServerAlias www.NAME.name
     Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"
    # the above is to enable HTTP Strict Transport Security (HSTS). That age is 2 years in seconds (2*365*24*60*60) which is OK for your project duration. 
    SSLEngine on
    SSLCertificateFile    PATH-TO-cert.pem-FILE
    SSLCertificateKeyFile PATH-TO-privkey.pem-FILE
    SSLCertificateChainFile PATH-TO-fullchain.pem-FILE 
    # Note that Name.name is an example for your domain and all PATH-* are file paths. Change them accordingly
    </VirtualHost>
    To force a redirect to HTTPS from HTTP include the below in your configuration:
    <VirtualHost *:80> 
    ServerName Name.name
      Redirect permanent / https://Name.name/
    </VirtualHost>
    ################################################
    Take a look at this as well:
    https://raymii.org/s/tutorials/HTTP_Strict_Transport_Security_for_Apache_NGINX_and_Lighttpd.html#Set_up_HSTS_in_Apache2
