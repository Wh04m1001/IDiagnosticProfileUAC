# IDiagnosticProfileUAC

Just another UAC bypass using auto-elevated COM object Virtual Factory for DiagCpl (12C21EA7-2EB8-4B55-9249-AC243DA8C666). This COM object can be used to create instance of DiagnosticProfile (D0B7E02C-E1A3-11DC-81FF-001185AE5E76) COM object which exposes SaveDirectoryAsCab method that can be used to move arbitrary file in system32 directory. This PoC copy user specified  dll to C:\Windows\System32\wow64log.dll and trigger MicrosoftEdgeUpdate service by creating instance of  Microsoft Edge Update Legacy On Demand COM object (A6B716CB-028B-404D-B72C-50E153DD68DA)  which run in SYSTEM context and will load wow64log.dll (more info [here](https://halove23.blogspot.com/2021/03/google-update-service-being-scum.html)).

This PoC is inspired by this awesome research from [@zcgonvh](https://github.com/zcgonvh)

http://www.zcgonvh.com/post/Advanced_Windows_Task_Scheduler_Playbook-Part.2_from_COM_to_UAC_bypass_and_get_SYSTEM_dirtectly.html (in chinaese)


![image](https://user-images.githubusercontent.com/44291883/177015112-908a6e50-ff25-4afa-b31a-86a60f18d901.png)
