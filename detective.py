import colorama
import re
import argparse
import requests
from jsbeautifier import beautify
import json
from bs4 import BeautifulSoup
import tomli
import warnings
from bs4 import GuessedAtParserWarning

warnings.filterwarnings("ignore", category=GuessedAtParserWarning)

regex = {
    "Cloudinary": "cloudinary://.*",
    "db_query": r"(\Uselect|\Udelete|\Uupdate|connect\(|sql|mysql|postgresql|sqlite)",
    "Firebase URL": ".*firebaseio\.com",
    "Slack Token": "(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})",
    "RSA private key": "-----BEGIN RSA PRIVATE KEY-----",
    "SSH (DSA) private key": "-----BEGIN DSA PRIVATE KEY-----",
    "SSH (EC) private key": "-----BEGIN EC PRIVATE KEY-----",
    "PGP private key block": "-----BEGIN PGP PRIVATE KEY BLOCK-----",
    "Amazon AWS Access Key ID": r"AKIA[0-9A-Z]{16}",
    "Amazon MWS Auth Token": r"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    "AWS API Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"[0-9a-zA-Z/+]{40}",
    "Amazon Marketing Services": r"amzn.mws.[0-9a-f]{8}-[0-9a-f]{4}-10-9a-f1{4}-[0-9a,]{4}-[0-9a-f]{12}",
    "amazon_aws_url2": r"("
    r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com"
    r"|s3://[a-zA-Z0-9-\.\_]+"
    r"|s3-[a-zA-Z0-9-\.\_\/]+"
    r"|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+"
    r"|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+)",
    "Base 64": r"^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)?$",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Facebook OAuth": r"[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|\"][0-9a-f]{32}['|\"]",
    "GitHub Personal Access Token (Classic)": r"^ghp_[a-zA-Z0-9]{36}$",
    "Github Personal Access Token (Fine-Grained)": r"^github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}$",
    "Github OAuth 2.0": r"^gho_[a-zA-Z0-9]{36}$",
    "Github User-to-Server Access Token": r"^ghu_[a-zA-Z0-9]{36}$",
    "Github Server-to-Server Access Token": r"^ghs_[a-zA-Z0-9]{36}$",
    "Github Refresh Token": r"^ghr_[a-zA-Z0-9]{36}$",
    "github_secrets": r"(g|G][i|I][t|T][h|H][u|U][b|B].*['|\"][0-9a-zA-Z]{35,40}['|\"]|GITHUB_SECRET|GITHUB_KEY|github_secret|github_key|github_token|GITHUB_TOKEN|github_api_key|GITHUB_API_KEY)[a-z_=\s\"'\:]{0,10}[^a-zA-Z0-9][a-zA-Z0-9]{40}[^a-zA-Z0-9]",
    "Generic API Key": r"[a|A][p|P][i|I][_]?[k|K][e|E][y|Y].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Generic Secret": r"[s|S][e|E][c|C][r|R][e|E][t|T].*['|\"][0-9a-zA-Z]{32,45}['|\"]",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google Cloud Platform OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google OAuth 2.0 Secret Key": r"[0-9a-zA-Z-_]{24}",
    "Google OAuth 2.0 Auth Code": r"4/[0-9A-Za-z-_]+",
    "Google OAuth 2.0 Access Token": r"ya29.[0-9A-Za-z-_]+",
    "Google Drive API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google Drive OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google (GCP) Service-account": '"type": "service_account"',
    "Google Gmail API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google Gmail OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Google OAuth Access Token": r"ya29\\.[0-9A-Za-z\\-_]+",
    "Google YouTube API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Google YouTube OAuth": r"[0-9]+-[0-9A-Za-z_]{32}\\.apps\\.googleusercontent\\.com",
    "Instagram OAuth 2.0": r"[0-9a-fA-F]{7}.[0-9a-fA-F]{32}",
    "Instagram Username": r"(?:@)([A-Za-z0-9_](?:(?:[A-Za-z0-9_]|(?:.(?!.))){0,28}(?:[A-Za-z0-9_]))?)",
    "Heroku API Key": r"[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
    "MailChimp API Key": r"[0-9a-f]{32}-us[0-9]{1,2}",
    "Mailgun API Key": r"key-[0-9a-zA-Z]{32}",
    "Password in URL": r"[a-zA-Z]{3,10}://[^/\\s:@]{3,20}:[^/\\s:@]{3,20}@.{1,100}[\"'\\s]",
    "PayPal Braintree Access Token": r"access_token\\$production\\$[0-9a-z]{16}\\$[0-9a-f]{32}",
    "Misc Personal Infromation": r"|dob=|ccn|^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$|",
    "SSN": r"^(\d{3}-?\d{2}-?\d{4}|XXX-XX-XXXX)$| ssn=",
    "Phone": r"((?:(?<![\d-])(?:\+?\d{1,3}[-.\s*]?)?(?:\(?\d{3}\)?[-.\s*]?)?\d{3}[-.\s*]?\d{4}(?![\d-]))|(?:(?<![\d-])(?:(?:\(\+?\d{2}\))|(?:\+?\d{2}))\s*\d{2}\s*\d{3}\s*\d{4}(?![\d-])))",
    "BTC Address": r"(?<![a-km-zA-HJ-NP-Z0-9])[13][a-km-zA-HJ-NP-Z0-9]{26,33}(?![a-km-zA-HJ-NP-Z0-9])",
    "Uploads": r"upload-fields",
    "JSON": r"json_file",
    "Email": r"(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|\"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9]))\.){3}(?:(2(5[0-5]|[0-4][0-9])|1[0-9][0-9]|[1-9]?[0-9])|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])",
    "Picatic API Key": r"sk_live_[0-9a-z]{32}",
    "Possible_Creds": r"(?i)("
    r"password\s*[`=:\"]+\s*[^\s]+|"
    r"password is\s*[`=:\"]*\s*[^\s]+|"
    r"pwd\s*[`=:\"]*\s*[^\s]+|"
    r"passwd\s*[`=:\"]+\s*[^\s]+)",
    "Credentials": r"(pwd|passwd|credentials|username|password|user|admin|root|administrator)",
    "IPv4": r"^\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}$",
    "IPv6": r"\b([\d\w]{4}|0)(\:([\d\w]{4}|0)){7}\b",
    "OpenAi User Api Key": r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    "OpenAi User Project Key": r"sk-proj-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    "OpenAI Service ID": r"^[A-Za-z0-9]+(-*[A-Za-z0-9]+)*$",
    "Open AI Service Key": r"sk-{SERVICE ID}-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}",
    "File Path": r"	\\[^\\]+$",
    "Slack Webhook": r"https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}",
    "Stripe API Key": r"sk_live_[0-9a-zA-Z]{24}",
    "Stripe Restricted API Key": r"rk_live_[0-9a-zA-Z]{24}",
    "Square Access Token": r"sq0atp-[0-9A-Za-z\\-_]{22}",
    "Square OAuth Secret": r"sq0csp-[0-9A-Za-z\\-_]{43}",
    "Twilio API Key": r"SK[0-9a-fA-F]{32}",
    "Twitter Access Token": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[1-9][0-9]+-[0-9a-zA-Z]{40}",
    "Twitter Username": r"/(^|[^@\w])@(\w{1,15})\b/",
    "Twitter OAuth": r"[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|\"][0-9a-zA-Z]{35,44}['|\"]",
    "Unknown_api": r"""(?i)(?:aws-keys|api_key=|api=|apisecret|access_key_id=|secret_key=|secret|access_token|refresh_token|privateKey|publicKey|key|token|client|auth|access)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\"|\s|=|\x60){0,5}([0-9a-z\-_.=]{10,150})(?:['|\"|\n|\r|\s|\x60|;]|$)""",
}


def main():
    print(
        f"""{colorama.Fore.CYAN}
     _      _            _   _                         
    | |    | |          | | (_)                        
  __| | ___| |_ ___  ___| |_ ___   _____   _ __  _   _ 
 / _` |/ _ \ __/ _ \/ __| __| \ \ / / _ \ | '_ \| | | |
| (_| |  __/ ||  __/ (__| |_| |\ V /  __/_| |_) | |_| |
 \__,_|\___|\__\___|\___|\__|_| \_/ \___(_) .__/ \__, |
                                          | |     __/ |
                                          |_|    |___/ 
        """
    )
    colorama.Fore.RESET

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u",
        "--url",
        type=str,
        help="URL pointing to the code you want to search, this url should end with a file extension ex .js (use this OR -f, NOT both )",
    )
    parser.add_argument(
        "-f",
        "--file",
        type=str,
        help="The path to the local file you want to search (use this OR -u, NOT both)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        help="Name of the file where the output should be written",
    )
    parser.add_argument(
        "-s",
        "--slow",
        action="store_true",
        help="Use this flag for a slower, but significantly more thorough search.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output, only use with the slow search",
    )

    args = parser.parse_args()

    test_input(args.file, args.url)
    if args.file:
        input = get_input_file(args.file, args.verbose)
    elif args.url:
        input = get_input_url(args.url, args.verbose)
    else:
        print(f"{colorama.Fore.RED}Please provide either a URL or a file path.")
        exit(1)

    if args.slow:
        slow_search(input, args)
    else:
        fast_search(input, args)


def get_input_file(file, verbose):
    """The function handles returning a strings containing the beautified contents of the input file

    Args:
        file (_type_): user specified file
        verbose (_type_): boolean indicating if user wants verbose output

    Returns:
        _type_: string
    """
    try:
        with open(file, "r") as f:
            file_string = f.read()
    except FileNotFoundError:
        print(f"{colorama.Fore.RED}File not found")
        exit(1)
    else:
        if verbose:
            print(f"{colorama.Fore.GREEN} File opened successfully!")
        if file.endswith(".js"):
            if verbose:
                print(f"{colorama.Fore.GREEN} Beautifying JavaScript file...")
            return beautify(file_string)
        elif file.endswith(".json"):
            if verbose:
                print(f"{colorama.Fore.GREEN} Beautifying JSON file...")
            return json.dumps(file_string, indent=2)
        elif file.endswith(".html"):
            if verbose:
                print(f"{colorama.Fore.GREEN} Beautifying HTML file...")
            print(file_string)
            return BeautifulSoup(file_string, "html")
        else:
            if verbose:
                print(f"{colorama.Fore.GREEN} Returning file of arbitrary type...")
            return file_string


def get_input_url(url, verbose):
    """If user has specified a URL, this function will scrape its contents and return a beautified string representation of it

    Args:
        url (_type_): user specified URL
        verbose (_type_): boolean indicating if the user specified verbose output

    Returns:
        _type_: string representation of the URL source code
    """
    try:
        request = requests.get(url)
    except (
        requests.exceptions.ConnectionError,
        requests.exceptions.Timeout,
    ) as e:
        print(f"{colorama.Fore.RED}A connection error or timeout occurred: {e}")
        exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"{colorama.Fore.RED}HTTP Error: {e}")
        exit(1)
    except requests.exceptions.RequestException as e:
        print(f"{colorama.Fore.RED}An error occurred: {e}")
        exit(1)
    else:
        if request.status_code == 200:
            request = request.text
            if verbose:
                print(
                    f"{colorama.Fore.GREEN} Connection established, parsing response..."
                )
            if url.endswith(".js"):
                if verbose:
                    print(f"{colorama.Fore.GREEN} Beautifying JavaScript...")
                return beautify(request)
            elif url.endswith(".json"):
                if verbose:
                    print(f"{colorama.Fore.GREEN} Beautifying JSON...")
                return json.dumps(request, indent=2)
            # assume that the url points to a random website thus we will search the websites html
            else:
                if verbose:
                    print(
                        f"{colorama.Fore.GREEN} Parsing and beautifying webpage to get HTML..."
                    )
                return BeautifulSoup(request, "html").prettify()


def test_input(file, url):
    """
    Tests the supplied user inputs before processing
    """
    if file is not None and url is not None:
        print(
            colorama.Fore.RED
            + "File and URL were both supplied, or neither were specified"
        )
        exit(1)
    elif file is None and url is not None:
        if url.strip().startswith("http://") or url.strip().startswith("https://"):
            return
        else:
            print(
                colorama.Fore.RED
                + "URL must start with 'http://' or 'https://' to be valid"
            )
            exit(1)
    elif file is not None and url is None:
        try:
            file = open(file, "r")
        except FileNotFoundError:
            print(f"{colorama.Fore.RED}File not found")
            exit(1)


def fast_search(input, args, output_file=None):
    """
    Handles the fast search, which is the default. Does not return anything, just prints or writes the results
    """

    if args.output is not None and output_file is None:
        output = get_output_file(args.output)

    elif output_file is not None and args.output is not None:
        output = output_file

    if args.output is None:
        print(
            "-----------------------------Fast Search Results-----------------------------"
        )

    if args.output is None and args.verbose:
        print("Starting fast search... ")
    elif args.output is not None and args.verbose:
        output.write("Starting fast search...\n")

    linecount = 0
    for line in str(input).splitlines():
        linecount += 1
        for key in regex.keys():
            words = line.split()
            for word in words:
                if len(word) > 200:
                    for indiv in word.split(","):
                        if matches := re.search(
                            regex[key],
                            indiv,
                            re.IGNORECASE,
                        ):
                            if args.output is None:
                                print(
                                    f"{colorama.Fore.GREEN}Potential Match Found! \nType: {key} \nMatch found in line {linecount}"
                                )
                                print(
                                    f"{colorama.Fore.BLUE}\nText that caused match: {indiv.strip()} + \nLine that caused match: {word.strip()}"
                                )
                                print(
                                    f"{colorama.Fore.RESET}-----------------------------------------------------------------"
                                )
                            else:
                                output.write(
                                    f"Potential Match Found! \nType: {str(key)} \nMatch found in line {linecount} \nText that caused match: {indiv.strip()}\nLine that caused match: {word.strip()}\n----------------------------------------------------------------\n"
                                )
                else:
                    if matches := re.search(
                        regex[key],
                        word,
                        re.IGNORECASE,
                    ):
                        if args.output is None:
                            print(
                                f"{colorama.Fore.GREEN}Potential Match Found! \nType: {key} \nMatch found in line {linecount}"
                            )
                            print(
                                f"{colorama.Fore.BLUE}\nText that caused match: {word.strip()} + \nLine that caused match: {line.strip()}"
                            )
                            print(
                                f"{colorama.Fore.RESET}-----------------------------------------------------------------"
                            )
                        else:
                            output.write(
                                f"Potential Match Found! \nType: {str(key)} \nMatch found in line {linecount} \nText that caused match: {word.strip()}\nLine that caused match: {line.strip()}\n----------------------------------------------------------------\n"
                            )


def slow_search(input, args):
    """
    Handles the slightly slower but more comprehensive slow search. Does not return anything just prints or writes the results and then calls the fast search function
    """
    with open("gitleaks.toml", "rb") as f:
        doc = tomli.load(f)
        rule_list = doc["rules"]
        if args.verbose:
            print(
                f"{colorama.Fore.CYAN} Parsing gitleaks.toml and running comprehensive search"
            )
        if args.output is not None:
            output = get_output_file(args.output)
            output.write(
                "-----------------------------Slow Search Results-----------------------------\n"
            )
        else:
            print(
                "-----------------------------Slow Search Results-----------------------------"
            )
        linecount = 0
        for line in str(input).splitlines():
            linecount += 1
            for rule in rule_list:
                words = line.split()
                for word in words:
                    # this increases accuracy if large blocks of text are submitted. The word that caused it will be much more accurate and mitigate huge blocks of text in output
                    if len(word) > 200:
                        for indiv in word.split(","):
                            if matches := re.search(
                                rule["regex"],
                                indiv,
                                re.IGNORECASE,
                            ):
                                if args.output is None:
                                    print(
                                        f"""{colorama.Fore.GREEN}Potential Match Found! Match ID: {rule["id"]} \nMatch found in line {linecount}"""
                                    )
                                    if args.verbose:
                                        print(f"Description: " + rule["description"])
                                    print(
                                        f"{colorama.Fore.BLUE}Text that caused match: {indiv} \nLine that caused match: {word}"
                                    )
                                    print(
                                        f"{colorama.Fore.RESET}-----------------------------------------------------------------"
                                    )
                                else:
                                    output.write(
                                        "Potential Match Found: \nMatch ID: "
                                        + rule["id"]
                                        + "\n"
                                        + " Match found in line "
                                        + str(linecount)
                                        + "\n"
                                    )
                                    if args.verbose:
                                        output.write(
                                            "Description: " + rule["description"] + "\n"
                                        )
                                    output.write(
                                        "Text that caused match: "
                                        + indiv
                                        + "\nLine that caused match: "
                                        + word
                                        + "\n----------------------------------------------------------------\n"
                                    )
                    # for "word"s that are less then 200 characters
                    else:
                        if matches := re.search(
                            rule["regex"],
                            word,
                            re.IGNORECASE,
                        ):
                            if args.output is None:
                                print(
                                    f"""{colorama.Fore.GREEN}Potential Match Found: \nMatch ID: {rule["id"]} Match found in line {linecount}"""
                                )
                                if args.verbose:
                                    print(f"Description: " + rule["description"])
                                print(
                                    f"{colorama.Fore.BLUE}Text that caused match: {word} \nLine that caused match: {line}"
                                )
                                print(
                                    f"{colorama.Fore.RESET}-----------------------------------------------------------------"
                                )
                            else:
                                output.write(
                                    "Potential Match Found: \nMatch ID: "
                                    + rule["id"]
                                    + "\n"
                                    + " Match found in line "
                                    + str(linecount)
                                    + "\n"
                                )
                                if args.verbose:
                                    output.write(f"Description: " + rule["description"])
                                output.write(
                                    "Word that caused match: "
                                    + word
                                    + "\nLine that caused match: "
                                    + line
                                    + "\n-----------------------------------------------------------------\n"
                                )
        if args.output:
            output.write(
                "\n\n-----------------------------Fast Search Results-----------------------------\n"
            )
            fast_search(input, args, output)
        else:
            if args.verbose:
                print(
                    f"{colorama.Fore.CYAN} Comprehensive search complete, beginning fast search..."
                )
            fast_search(input, args)


def get_output_file(output):
    return open(output, "a+")


if __name__ == "__main__":
    main()
