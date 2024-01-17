# Verifiable Credential Validator

> Validate your W3C Verifiable Credential (https://www.w3.org/TR/vc-data-model/) in a simple step-by-step manner

## Install dependencies

Before running this validator, you will need to install the required dependencies with the following command.

```shell
pip3 install -r requirements.txt
```

Although it doesn't need to be installed, this application uses [DIF's Universal Resolver](https://dev.uniresolver.io/) to 
resolve DID documents, a special thanks goes out to their team.

## How to use ?

Just run the `main.py` script with the path to the JSON file containing your Verifiable Credential as an argument.

For example :

```shell
python main.py verifiable-credential.json
```