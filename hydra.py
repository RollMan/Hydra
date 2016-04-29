# -*- coding: utf-8 -*-
import util
import sys, decode, datetime, os

apikey = '*****'
apisec = '*****'

def req(url, content, method):
  return util.request(apikey, apisec, authorize_keys["oauth_token"], authorize_keys["oauth_token_secret"], url, content, method)
def date2int(datestr):
  date = datetime.datetime.strptime(datestr, "%a %b %d %H:%M:%S %z %Y")
  return date
  

class timeline:
  time_begin = 0
  time_end   = 0
  hashtag = ''
  tweetlist  = []

  def __init__(tb, te, ht):
      time_begin = tb
      time_end = te
      hashtag = ht

  def fetchTweets():
    res = req("https://api.twitter.com/1.1/search/tweets.json", {'q':hashtag, 'until':time_end}, 'GET')
    res = json.loads(res.decode('utf-8'))
    self.tweetlist+=res
    while(time_end > self.tweetlist[-1]["created_at"]):
      res = req("https://api.twitter.com/1.1/search/tweets.json", {'q':hashtag, 'until':time_end, 'since_id':self.tweetlist[-1]['id']}, 'GET')
      res = json.loads(res.decode('utf-8'))
      self.tweetlist += res
  #def start():

def main():
  if sys.argc is not 5*2+1+1:
    print("Usage: " + sys.argv[0] + "[begin_year] [begin_month] [begin_day] [begin_hour] [begin_minute] [end_year] [end_month] [end_day] [end_hour] [end_minute] [hashtag]")
  time_begin = datetime.datetime(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]);
  time_end = datetime.datetime(sys.argv[6], sys.argv[7], sys.argv[8], sys.argv[9], sys.argv[10]);
  hashtag = sys.argv[11]
  tl = timeline(time_begin, time_end, hashtag)

  for i in tl.tweetlist:
    print(i["status"])

if __name__ == '__main__':
  authorize_filename = "authorization.txt"
  if os.path.isfile(authorize_filename):
    authorize_keys = authorize_twitter(apikey, apisec)
    authorize_file = open(authorize_filename, 'w')
    authorize_file.write(authorize_keys)
  else:
    authorize_file = open(authorize_filename, 'r')
    authorize_keys = json.load(authorize_filejson.load(authorize_file))

  main()
  exit(0)
