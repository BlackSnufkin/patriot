# Patriot
![Patriot_missile_launch_b](https://user-images.githubusercontent.com/56411054/178175726-bc2c843c-103e-4366-8221-45d64a033e00.jpg)

Small research project for detecting various kinds of in-memory stealth techniques. 

Download the latest release [here](https://github.com/BlackSnufkin/patriot/releases/download/v0.3.1/Patriot.zip).

The current version supports the following detections:
- Suspicious CONTEXT structures pointing to VirtualProtect functions. (Targets [research](https://suspicious.actor/2022/05/05/mdsec-nighthawk-study.html) by Austin Hudson [Foliage](https://github.com/y11en/FOLIAGE/tree/master/source) and [Ekko](https://github.com/Cracked5pider/Ekko) by Cracked5pider).
- Validation of MZ/PE headers in memory to detect process hollowing variants.
- Unbacked executable regions running at high integrity.
- Modified code used in module stomping/overwriting.
- Various other anomalies.

![patriot-p](https://github.com/user-attachments/assets/b2167c05-3714-439a-95a5-c122012df22b)

![patriot-f](https://github.com/user-attachments/assets/7c1b1721-d603-47f6-a124-cc51c8c7c8b2)
