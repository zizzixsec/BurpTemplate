from burp import IBurpExtender, IScannerCheck, IScanIssue

class BurpExtender(IBurpExtender, IScannerCheck):
	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()
		callbacks.setExtensionName("Burp Template")
		callbacks.registerScannerCheck(self)
		callbacks.issueAlert("Registered Burp Template...")
		print( "Burp Template extension loaded." )
		return

	def getResponseHeadersAndBody(self, content):
		response = content.getResponse()
		response_data = self._helpers.analyzeResponse(response)
		headers = list(response_data.getHeaders())
		body = response[response_data.getBodyOffset():].tostring()
		return headers, body


	def doPassiveScan(self, baseRequestResponse):
		issues = []
		headers, body = self.getResponseHeadersAndBody(baseRequestResponse)
        
		# Test the body for GUIDs
		# if self.valid_v1_uuid(body):
		# 	self._callbacks.issueAlert("Found potential valid v1 UUID in body. Check Issue Activity!")
			
		# 	# report the issue
		# 	issues.append( UUIDScanIssue(
		# 		baseRequestResponse.getHttpService(),
		# 		self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
		# 		[baseRequestResponse]
		# 	))

		# if not issues:
		# 	issues = None 

		return issues
	
	def doActiveScan(self, baseRequestResponse, insertionPoint):
		pass

	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		if existingIssue.getIssueName() == newIssue.getIssueName():
			return -1
		return 0
		
class UUIDScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages

    # def getUrl(self):
    #     return self._url

    # def getIssueName(self):
    #     return "Possible v1 UUID detected"

    # def getIssueType(self):
    #     return 0

    # def getSeverity(self):
    #     return "Medium"

    # def getConfidence(self):
    #     return "Certain"

    # def getIssueBackground(self):
    #     pass

    # def getRemediationBackground(self):
    #     pass

    # def getIssueDetail(self):
    #     return "The response contains a potential v1 UUID, which is prone to attack. See: https://danaepp.com/attacking-predictable-guids-when-hacking-apis"

    # def getRemediationDetail(self):
    #     pass

    # def getHttpMessages(self):
    #      return self._httpMessages

    # def getHttpService(self):
    #     return self._httpService