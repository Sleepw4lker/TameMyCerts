## Configuring the expiration date of issued certificates to fall inside defined time windows

> Applies to **online** and **offline** certificate templates.

As a PKI operator, we have the challenge that our users might forget renewign their service's certificates in time. This can lead to service outages, and the damage is multiplied when a certificate expires outside of support hours.


### Configuring

The `TimeWindows` directive allows to configure a list of `TimeWindow` entries that define time windows in which we allow certificates to expire. If configured, TameMyCerts will calculate the nearest of the defined time windows in relation to the original expiration date set by the certification authority process. It will then modify the `NotAfter` property of the issued certificate so that it will expire within the defined time window.

|Parameter|Mandatory|Description|
|---|---|---|
|`Day`|yes|Specifies the day of the week for the given time window. It must be specifief in english language, like `Monday`,`Tuesday`,`Wednesday`,`Thursday`,`Friday`,`Saturday`,`Sunday`|
|`Start`|yes|Specifies the start of the time range, specified in Universa, (UTC) time zone.|
|`End`|yes|Specifies the start of the time range, specified in Universa, (UTC) time zone.|

> Note that the expiration time will be randomly chosen within the respective range between `Start` and `End`.

### Examples

The below configuration ensures that each issued certificate has an expiration time that falls within either Monday from 09:00 to 17:00 (UTC) or Wednesday from 09:00 to 12:00 (UTC).

```xml
<TimeWindows>
  <TimeWindow>
    <Day>Monday</Day>
    <Start>09:00:00</Start>
    <End>17:00:00</End>
  </TimeWindow>
  <TimeWindow>
    <Day>Wednesday</Day>
    <Start>09:00:00</Start>
    <End>12:00:00</End>
  </TimeWindow>
</TimeWindows>
```