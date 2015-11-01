from libmproxy.protocol.http import decoded


def response(context, flow):
    if flow.response.headers.get_first("content-type", "").startswith("image"):
    	with decoded(flow.response):
            try:
            	img = cStringIO.StringIO(open('freebuf.jpg', 'rb').read())
            	flow.response.content = img.getvalue()
            	flow.response.headers["content-type"] = ["image/jpg"]
            except:
                pass
