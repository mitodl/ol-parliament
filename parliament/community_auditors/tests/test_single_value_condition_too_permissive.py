from parliament import analyze_policy_string


class TestSensitiveAccess:
    """Test class for single value condition too permissive auditor"""

    def test_single_value_condition_too_permissive(self):
        example_policy_string = """
        {
          "Version": "2012-10-17",
          "Statement": [
            {
              "Effect": "Allow",
              "Action": [
                "s3:GetObject"
              ],
              "Resource": "arn:aws:s3:::secretbucket/*",
              "Condition": {
                  "ForAllValues:StringEquals": {
                      "aws:ResourceTag/Tag": [
                          "Value"
                      ]

                  }
              }
            }
          ]
        }
        """
        policy = analyze_policy_string(
            example_policy_string, include_community_auditors=True
        )
        assert policy.finding_ids == set(["SINGLE_VALUE_CONDITION_TOO_PERMISSIVE"])
