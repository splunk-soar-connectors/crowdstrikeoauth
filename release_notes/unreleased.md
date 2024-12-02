**Unreleased**

* EPPDetectionSummaryEvent events are now additionally ingested during 'on_poll' [PAPP-34988]
* Added 'list_epp_alerts' action to connector [PAPP-34988]
    * Lists new EPP alerts that are replacing detections
    * Should be used over 'list detections' action (Deprecating April 30, 2025)
* Added 'get_epp_alerts_details' action to connector [PAPP-34988]
    * Gets details for EPP alerts
    * Should be used over 'get detections details' action (Deprecating April 30, 2025)
* Added 'update_epp_alerts' action to connector [PAPP-34988]
    * Updates EPP alerts
    * Should be used over 'update detections' action (Deprecating April 30, 2025)
* Added 'resolve_epp_alerts' action to connector [PAPP-34988]
    * Changes status of EPP alerts
    * Should be used over 'resolve detection' action (Deprecating April 30, 2025)
