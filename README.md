## Python-Nessus

python-nessus is a **Rest Api Client** written in python, which provides the user facility to automate vulnerability scanning using Nessus REST API.

Depending on the flag issued, it can *list all policies*, *create and launch the scan*, *configure the user-defined policy prior to launching the scan* and *export the report in all available formats* except for pdf. The command line utility has the *power* to do all this just by entering a single command.

## Pre-Requisites
```
python2.x
Nessus 6 or above
pip for python2.x
```
## Installation

Ideally, you should be able to just type:

```
git clone https://github.com/AdmiralGaust/python-nessus.git
cd python-nessus
sudo chmod u+x python-nessus
PATH=$PATH:/path/to/current_directory
pip install requests argparse termcolor
```
In case something not works, you can simply copy the python-nessus file to a text editor and save it as **_python-nessus.py_**
After saving the file, install the *dependencies* by typing `pip install requests argparse termcolor`

## Using *Python-nessus*

Open the python-nessus file with your favourite text editor and fill in the username and password fields at line 56 and 57 with your username and password.
Now,to get the help menu type `python-nessus`

Make sure python-nessus is in your PATH. If it is not, you will encounter an error `command not found`.
I will recommend you to add _python-nessus_ to the PATH variable. Although, you can fix this issue by using it as `python python-nessus`

## Examples of Usage
To list all policies :

```
python-nessus --list-policies
```

To create and launch a scan

```
python-nessus -t target_ip -p "policy_name"
```

To create and launch a scan taking targets from a text file

```
python-nessus -T target_file -p "policy_name"
```

To launch the scan with a customized name and export the report in csv format

```
python-nessus -T target_file -p "policy_name" -n scan_name -e csv
```

To delete the scan after exporting the report

```
python-nessus -T target_file -p "policy_name" -e html --delete
```

To configure the User-defined policy prior to launching the scan

```
python-nessus -t target_ip -p "policy_name" --configure -e nessus
```

## SUPPORT
This repository is no longer supported. 
