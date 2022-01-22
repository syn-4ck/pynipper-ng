class CiscoIOSIssue:

    def __init__(self, title, observation, impact, ease, recommendation):
        self.title = title
        self.observation = observation
        self.impact = impact
        self.ease = ease
        self.recommendation = recommendation

    def __str__(self):
        print("Issue " + self.title + ":")
        print("===================================================================================================")  # noqa: E501
        print("Observation: " + self.observation)
        print("Impact: " + self.impact)
        print("Ease: " + self.ease)
        print("Recommendation: " + self.recommendation)
        print("\n---------------------------------------------------------------------------------------------------")  # noqa: E501
        return("")

    def __dict__(self):
        d = {}
        d['title'] = self.title
        d['observation'] = self.observation
        d['impact'] = self.impact
        d['ease'] = self.ease
        d['recommendation'] = self.recommendation
        return d
