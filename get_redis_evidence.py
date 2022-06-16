import redis
import json
r = redis.Redis(host='localhost', port=6379, db=1)
# json_content = json.loads(r.hmget('evidenceprofile_192.168.0.134',['timewindow0'])[0])
# print(list(json_content.keys()))
print(r.hmget('evidenceprofile_192.168.0.134',['timewindow2']))