class CiscoVuln:

    def __init__(self, title, summary, cves, cvss, url):
        self.title = title
        self.summary = summary
        self.cves = cves
        if (cvss == 'NA'):
            cvss = 0.0
        self.cvss = float(cvss)
        self.url = url

    def __str__(self):
        print("Vulnerability " + self.title + ":")
        print("===================================================================================================")
        print("Summary: " + self.summary)
        print("CVEs: " + str(self.cves))
        print("CVSS: " + self.cvss)
        print("Publication URL: " + self.url)
        print("\n---------------------------------------------------------------------------------------------------")
        return("")

    def __eq__(self, other):
        return self.title == other.title

    def __lt__(self, other):
        return self.cvss < other.cvss
