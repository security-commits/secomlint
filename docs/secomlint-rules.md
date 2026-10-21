# Rules

Rules are made up by a name and a configuration array. The configuration array contains:

* **active** ``[0,1]``: `0` disables the rule; `1` enables the rule. By default it is enabled.
* **type** ``[0,1]``: `0` reports an warning; `1` reports an error. 
* **value**: value to use for the rule.

<br>

Some of the `value` fields are extracted by the named entity recognition (NER) [engine](engine.md#architecture). Those values are called entities and can have different [types](engine.md#entities). In addition, the tool considers a message is divided into five main sections: **header**, **body**, **metadata**,
**contact** and **bug-tracker** references.   

<br>

#### header-max-length
* **condition**: `header` has `value` or less characters
* **type**: 0 (warning)
* **value**: 50


#### header-is-not-empty
* **condition**: `header` has more than 0 characters
* **type**: 1 (error)
* **value**: 0


#### header-starts-with-type

* **condition**: `header` starts with `<type>` 
* **type**: 1 (error)
* **value**: `vuln-fix`


#### header-ends-with-vuln-id

* **condition**: `header` ends with `<vuln-id>` 
* **type**: 0 (warning)
* **value**: `VULNID`


#### body-is-not-empty

* **condition**: `body` has more than 0 characters
* **type**: 1 (error)
* **value**: 0


#### body-max-length

* **condition**: `body` has `value` or less characters
* **type**: 0 (warning)
* **value**: 75


#### body-has-three-paragraphs

* **condition**: `body` has three paragraphs
* **type**: 1 (error)


#### metadata-has-weakness

* **condition**: `metadata` has tag `weakness:` followed by `CWEID`
* **type**: 1 (error)


#### metadata-has-severity

* **condition**: `metadata` has tag `severity:` followed by `SEVERITY`
* **type**: 1 (error)


#### metadata-has-detection

* **condition**: `metadata` has tag `detection:` followed by `DETECTION`
* **type**: 0 (warning)


#### metadata-has-report

* **condition**: `metadata` has tag `report:` followed by `URL`
* **type**: 0 (warning)


#### metadata-has-cvss

* **condition**: `metadata` has tag `cvss:` 
* **type**: 0 (warning)


#### metadata-has-introduced-in

* **condition**: `metadata` has tag `introduced in:` followed by `SHA` 
* **type**: 0 (warning)


#### contact-has-reported-by

* **condition**: `contact` has tag `reported-by:` AND `EMAIL`
* **type**: 0 (warning)


#### contact-has-signed-off-by

* **condition**: `contact` has tag `signed-off-by:` AND `EMAIL`
* **type**: 0 (warning)


#### contact-co-authored-by

* **condition**: `contact` has tag `co-authored-by:` AND `EMAIL`
* **type**: 0 (warning)

#### bugtracker-has-reference

* **condition**: `bugtracker` has (tag `bug-tracker:` AND `URL`) OR (tag `resolves: .. see also:` AND `ISSUE`)
* **type**: 0 (warning)