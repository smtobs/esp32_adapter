# ESP32 어댑터 드라이버
- Raspberry Pi에서 동작하는 ESP32 Wi-Fi 어댑터 디바이스 드라이버
- ESP32 어댑터 드라이버 소스코드 주소 : https://github.com/smtobs/esp32_adapter.git
- ESP32 모듈 소스코드 주소 : https://github.com/smtobs/esp32_module.git
## 개발환경
- H/W : 라즈베리파이4, esp32 devkit v1 
- OS : Raspberry Pi OS, Kernel 5.10.103
- Program Language : C
- Tools : WireShark, VScode, MobaXterm
  
## 시스템 구조
![image](https://github.com/smtobs/esp32_adapter/assets/50127167/42ce9ebb-83e3-4495-997b-a3e1706e58a4)

- 유저 영역과 Wi-Fi 드라이버가 통신을 하기 위하여 cfg80211 등록
- iw dev scan 기능을 수행 하기 위하여 Wi-Fi의 관리 프레임을 생성 및 파싱 (probe request 생성, probe response 파싱)
- ping 명령어의 ICMP Request와 Reply 패킷을 송 수신하기 위하여 네트워크 디바이스 등록을 통하여 네트워크 인터페이스 생성
- 네트워크 디바이스에게 전달 된 패킷의 이더넷 헤더를 분해하여 Wi-Fi 데이터 프레임을 생성 후 SPI 인터페이스로 송신
- SPI 인터페이스로 수신 된 Wi-Fi 데이터 패킷을 이더넷 프레임으로 변경 후 네트워크 디바이스에게 전달
- 사용자 영역에서 Wi-Fi Driver를 제어를 위한 vendor commands를 적용하여 커스텀 명령어 적용. (Wi-Fi 연결을 해제 하기 위한 deauthentication 프레임 생성)
- Wi-Fi 프레임을 처리하기 위한 ESP32 모듈 Firmware 개발

## 동작 결과
- iwconfig, ifconfig 인터페이스 출력
![image](https://github.com/smtobs/esp32_adapter/assets/50127167/5e425151-4fe2-48bc-89ca-2d712f8411c2)

- scan 동작 결과
![image](https://github.com/smtobs/esp32_adapter/assets/50127167/017e4fee-c9ba-456c-9deb-486dbf0518cf)

- ping 동작 결과
![image](https://github.com/smtobs/esp32_adapter/assets/50127167/2e5febbc-8b32-404d-8158-a10790966fad)


## 참고사항
- 802.11 Wireless Networks: The Definitive Guide (The Definitive Guide) [저자 : Gast, Matthew]

