# detective.py

#### Command-Line Arguments:

-u, --url - Use this flag to specify the URL you would like to search. This could be an online file or just a normal web page. If it's the latter, the tool will scrape the HTML and search that. Use this flag OR the file flag, not both.

-f, --file - Use this flag to specify the file that you wish to search. Use this flag OR the URL flag, not both.

-s, --slow - Use this flag for a slower, but more comprehensive search. This will likely lead to more output and potentially more results.

-v, --verbose - Use this flag for slightly more verbose output

-o, --output - Use this flag to specify a name for a file whereby the output will be written. Note using this flag means nothing with shown on the console.

#### Example Usage:

python3 project.py -u https://test.com --slow -o test.txt
<br>
python3 project.py -f path/to/somecode.js -v

#### Description:

This project was made as my final project for Harvard's CS50P course. 

Detective.py is a cybersecurity tool designed to highlight potentially sensitive information in a piece of code. This sensitive information could include credentials, API keys, or database information.
This search is done by parsing the provided input whether it be a file or URL, and checking each word of this input against this library of regular expressions. One of the challenges
of accurately checking each word is formatting ugly inputs or blocks of code into standard lines. I leveraged a few popular libraries to check for a few different file types (mainly
ones commonly found on websites) and beautify them accordingly. This beautification is key to the output as accurate as possible. I aim to provide the exact word that caused
the match in the output. Then also provide the line whereby the match was contained. Especially on websites one often sees huge ugly blocks of javascript or some type of code, so I wanted to mitigate these huge chunks of code ending up in the output. I was fairly successful in doing so, it cannot always be avoided but I did implement checks to reduce it
as much as I could. Most code written in local files is already formatted to some degree, so I mainly only beautified common files found on websites.

gitleaks.toml contains the rules used only for the "slow" search. project.py is the actual search program. test_project.py is a pytest tester that was required for the final project. requirements.txt contains all of the necessary libraries. test.py was just a testbed I used during the creation of the main program. words.txt is a compilation of all the words and regular expressions used.

Originally I planned to only search .js and .json files. I eventually considered how much more useful this tool would be if I accepted all file types. I then implemented functionality
to automatically scrape a website's code if the URL provided did not explicitly point to a specific file. In my opinion, this feature makes the tool much more versatile and allows users of the tool to easily search any content found on the internet.

I have always been a huge fan of the programming community and epically the open-source community. Through my journey of learning programming, I have been amazed and inspired by all of the free tools and resources I have been able to find and use. I very quickly felt inspired to give back to this wonderful community and do what I can to help people learn and experiment for free. This inspiration led me to create this tool for my final project. I believe this tool could potentially help both the open-source community and enterprises. Almost all companies have at least one asset online, and in the open-source community, they are posting their code for anyone. This tool could potentially help both parties run a quick and fairly comprehensive search for sensitive information in their code before deployment. It's not uncommon for developers to leave commented-out credentials in their code or potentially leave an API key in their code from their testing. Either of these scenarios could potentially lead to security concerns if people find this information. I am also very interested in website design/ security and bug bounties. I could see this tool as being genuinely useful for quick testing in any of these scenarios. My ultimate goal is to increase somebody's code security and provide value to this community that has provided so much value to me.

Thank you for using this tool!

Credits:

- https://github.com/m4ll0k for the regular expressions
- https://github.com/zricethezav/gitleaks for the regular expressions

