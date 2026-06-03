# Task:
More and more junk is coming through our contact form—bots, strange emails, the same messages sent multiple times. We have logs from January (submissions.csv file, ~10k lines). Write a script that will analyze this and tell me how much spam there is, who's sending it, and what we can block. I don't need an app—just run it locally and show the results.
# How to run:

    python analyze.py data/submissions.csv
### flags:
    --since -> date
    --to -> date
### example: 
    python analyze.py --since 2025-01-05 --to 2025-01-15

## Directory for files to analyze: 
/data/

## Where plots are placed:
/report/plots/

### conclusions_pattern.py 
-> how conclusions.py should look
