class Issue:

    def __init__(self, title, observation, impact, ease, recommendation, cis_section=None):
        self.title = title
        self.observation = observation
        self.impact = impact
        self.ease = ease
        self.recommendation = recommendation
        self.cis_section = cis_section or "N/A"

    def __str__(self):
        print("Issue " + self.title + ":")
        print("===================================================================================================")  # noqa: E501
        print("CIS Section: " + self.cis_section)
        print("Observation: " + self.observation)
        print("Impact: " + self.impact)
        print("Ease: " + self.ease)
        print("Recommendation: " + self.recommendation)
        print("\n---------------------------------------------------------------------------------------------------")  # noqa: E501

    def __dict__(self):
        d = {}
        d['title'] = self.title
        d['cis_section'] = self.cis_section
        d['observation'] = self.observation
        d['impact'] = self.impact
        d['ease'] = self.ease
        d['recommendation'] = self.recommendation
        return d
