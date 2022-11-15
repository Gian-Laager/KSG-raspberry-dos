FROM arm32v7/rust

RUN apt-get update -y
RUN apt-get upgrade -y
RUN apt-get install nmap -y
RUN apt-get install hashcat -y
RUN apt-get install wget -y



