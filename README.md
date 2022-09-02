# TheHive-MitreProject
Project developped during an internship experience in the SOC division of Yarix Srl, a cybersecurity company.<br>
In this company [The Hive Project](https://thehive-project.org/) is used to manage all security events created by the monitoring systems installed in the clients networks. In the main page of this open source platform there are thousands of cases which cointain a single dangerous event that needs to be check by a security technician. Every case contains a specific page where it's possible to insert a TTP (Tactics, Techniques and Procedures) related to [Mitre ATT&CK framework](https://attack.mitre.org/) 

## Goals
The requests for this activity was two:
1. Create a WEB API used to request all the Mitre categories related to a specific alert (and update database with new alerts or new alert-TTP relations) 
2. Create a WEB interface to modify alerts-TTP relations (it needed to be easy to use in order to simplify technician work)

## Structure
There are two folders, one for the database management (classes, utility functions,..), the other for WEB functionalities (api and web interface).

## Examples
Inside [Images](/Images) folder there are all the screenshot showing the web interface. More specifically, there are: 
1. [Main page](/Images/Home.png)
2. [Display all Mitre enterprise framework](/Images/DisplayAllCategories.png) and a [single Mitre category](/Images/DisplayCategories.png)
3. [Page to create alert-TTP relations](/Images/Alerts_blur2.png)
4. [Table displaying existing relations](/Images/MatchedAlerts.png)
5. [Tools page](/Images/Tools2.png) 
6. [Error main page](/Images/Error.png)
7. [WebAPI request-response example](/Images/Postman-AV_4_blur.png) with Postman
8. [The resulting TTP page of a test case](/Images/TheHiveResult.png) (The Hive Project)

## Documentation
There isn't a real documentation for this project since it wasn't required from the supervisor. There are comments in every file to explain features and reasonings behind the code. <br> 
The only [document](Schema%20database%20mitrettp.pdf) written and uploaded here, it's the DB sctructure and its contraints.
