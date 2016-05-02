import urllib
import util
apikey = "***"
apisec = "***"

tw = util.Twitter()
tw.authorize_twitter(apikey, apisec)
print(type(tw.oauth_token))
res = tw.request(apikey, apisec, "https://api.twitter.com/1.1/statuses/update.json", {'status':'maaya uchida'}, "POST")
print(res)
