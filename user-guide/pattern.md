## Description of the "Pattern" directive {#pattern}

The **Pattern** parameter is defined as follows:

|Parameter|Mandatory|Description|
|---|---|---|
|Expression|**yes**|Specifies the expression the field gets matched against.|
|TreatAs|no|Specifies how the expression is to be interpreted by TameMyCerts. Defaults to _RegEx_.|
|Action|no|Specifies if a match for the pattern will "Allow" the certificate to get issued (the default) or "Deny" the certificate request.|

The **TreatAs** directive can be configured to one of the following values:

|Value|Description|
|---|---|
|RegEx|Treat the value to be analyzed as a **case sensitive** regular expression (the default).|
|RegExIgnoreCase|Treat the value to be analyzed as a **case insensitive** regular expression.|
|Cidr|Treat the value to be analyzed as an IP address that must be within an IPv4 or IPv6 subnet in CIDR notation, e.g. 192.168.0.0/16.|
|ExactMatch|The value to be analyzed must exactly match the configured expression (**case sensitive**).|
|ExactMatchIgnoreCase|The value to be analyzed must exactly match the configured expression (**case insensitive**).|
