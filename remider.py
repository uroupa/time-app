import pandas
import sqlite3
import datetime as dt
import smtplib

dev_email = "admin@user_email.com"
password = "pass"

# to be run every hour
hour_now = str(dt.datetime.now()).split(' ')[1].split(':')[0]
# print(hour_now)

one_hour_from_now = str(int(hour_now) + 1)
if len(one_hour_from_now) < 2:
    one_hour_from_now = f'0{one_hour_from_now}'

# Read sqlite query results into a pandas DataFrame
con = sqlite3.connect("blog.db")
df = pandas.read_sql_query("SELECT * from scheduler", con)

# rename columns
df.rename(columns={'six': '06', 'seven': '07', 'eight': '08', 'nine': '09',
                   'ten': '10', 'eleven': '11', 'twelve': '12', 'thirteen': '13', 'fourteen': '14', 'fifteen': '15',
                   'sixteen': '16',
                   'seventeen': '17', 'eighteen': '18'}, inplace=True)

try:
    messages = {row['author_email']: row[one_hour_from_now] for index, row in df.iterrows() if
                len(row[one_hour_from_now]) > 1}
except KeyError:
    print(f'KEY ERROR. \'{one_hour_from_now}\' is not a column')
else:
    if not messages:
        print('No messages to send.')
        pass
    else:
        print(messages)
        for user_email, message in messages.items():
            with smtplib.SMTP("smtp.gmail.com", 587) as connection:
                connection.starttls()
                connection.login(user=dev_email, password=password)
                connection.sendmail(
                    from_addr=dev_email,
                    to_addrs=user_email,
                    msg=f"Subject:Your Scheduled Reminder Notification\n\nDear User:\nThis is a reminder for \'{message}\' on your schedule on time-app.com."
                )
con.close()
