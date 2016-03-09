#!/usr/bin/env python

from collections import Counter

__author__ = "Rakesh"

yara_file = "/Users/rakesh/Downloads/rules.yara"

with open(yara_file) as f:
    data = f.read()
rules = {}
inside_comment = 0

# The below variables are optional. I just used them to get specific information
total_public_rules = 0
total_private_rules = 0
total_private_mal_rules = 0
total_public_mal_rules = 0
weights = []

# Actual parsing of rules starts here
for line in data.splitlines():
    line = line.replace('\n', '').replace('\r', '')
    if inside_comment:
        continue
    if line.startswith("/*"):
        inside_comment = 1
        continue
    elif line.startswith("*/"):
        inside_comment = 0
        continue
    if line.startswith("private rule"):
        rule = line.split()[-1].strip()
        private = 1
        total_private_rules += 1
    elif line.startswith("rule"):
        rule = line.split()[-1].strip()
        private = 0
        total_public_rules += 1
    elif line.strip().startswith("rule_name"):
        rule_name = line.split("=")[-1].strip().replace('"', '').strip()
    elif line.strip().startswith("display_name"):
        display_name = line.split("=")[-1].strip().replace('"', '').strip()
    elif line.strip().startswith("weight"):
        weight = int(line.split("=")[-1].strip())
        weights.append(weight)
        if weight == 100:
            if private:
                total_private_mal_rules += 1
            else:
                total_public_mal_rules += 1
    elif line.strip().startswith("created_date"):
        created_date = line.split("=")[-1].strip().replace('"', '').strip()
    elif line.strip().startswith("description"):
        description = line.split("=")[-1].strip().replace('"', '').strip()
    elif line.strip() == "}":
        rules[rule] = {'rule_name': rule_name, 'display_name': display_name, 'weight': weight, 'created_date': created_date, 'description': description, 'private': private}
    else:
        pass

# Use "rules" dictionary to get the information you need.

# The below code is optional. I needed specific information, you don't need this.
counter = Counter(weights)
total_rules = total_private_rules + total_public_rules
print "Total Rules : %s" % str(total_rules)
print "Total Public Rules: %s" % str(total_public_rules)
print "Total Private Rules: %s" % str(total_private_rules)
print "Total Public Rules with weight 100: %s" % str(total_public_mal_rules)
print "Total Private Rules with weight 100: %s" % str(total_private_mal_rules)
print "Weight distribution: %s" % counter
