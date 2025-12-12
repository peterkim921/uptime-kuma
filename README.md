# LSAP GROUP ONE: Uptime Kuma

Uptime Kuma is an easy-to-use self-hosted monitoring tool.
Here is the link to original repo: https://github.com/louislam/uptime-kuma

## ⭐ Features

- Generating a professional report for all monitor performance
- Allowing users to monitor reports using a custom time range
- DNS wildcard function
- Filtering out IP input from the DNS monitor.
- Double notification: sending notification to another user after pre-defined time period.

## ⭐ Motivations
Regarding the DNS monitoring features, we discovered an existing issue in the original repository that we believe we can resolve.Here is the link to that issue: https://github.com/louislam/uptime-kuma/issues/6444

As for the other proposed features, we can proudly say that we conceived them entirely ourselves. We personally cloned and used the repository, identified several areas that could be significantly improved. After several discussions, and utilizing AI to help clarify our ideas, we are now proposing these wonderful features.

## ⭐ How to Install

Requirements:

- Platform
  - ✅ Major Linux distros such as Debian, Ubuntu, Fedora and ArchLinux etc.
  - ✅ Windows 10 (x64), Windows Server 2012 R2 (x64) or higher
  - ❌ FreeBSD / OpenBSD / NetBSD
  - ❌ Replit / Heroku
- [Node.js](https://nodejs.org/en/download/) >= 20.4
- [Git](https://git-scm.com/downloads)

```bash
git clone https://github.com/louislam/uptime-kuma.git
cd uptime-kuma
npm run setup
node server/server.js
```


## ⭐ How to use our features
First of all, try to set up some monitors by yourself.
- Generating a professional report for all monitor performance

  Clicking and report button on the upper right, and the report just like below would be downloaded.
  <img width="1599" height="343" alt="image" src="https://github.com/user-attachments/assets/76221298-fb1b-4b3d-a690-0c183b2d4183" />

- Allowing users to monitor reports using a custom time range

  Choosing the time period button, select the 'Self-Defined' option, and then specify both a start time and an end time.
  <img width="1409" height="300" alt="image" src="https://github.com/user-attachments/assets/20448981-5a8f-432c-ad74-1e2cb8432c79" />

- DNS wildcard function

  1. Try to add a new DNS monitor.
  2. Input a wildcard domain into hostname (for example, *.github.io).
  3. (Optional) Choose the heartbeat period, the warning notification would pop up to alert users that short time period may cause low DNS cache performance.
  4. Go back to dashboard and wait for outputs.
  <img width="864" height="675" alt="image" src="https://github.com/user-attachments/assets/c3989ab0-f4df-4e83-9877-2738d98d32c9" />

- Double notification: sending notification to another user after pre-defined time period.

  1. Add a monitor with notification alert.
  2. Set two platforms and the pre-defined time period for upcoming notifications.
  3. [use api-test to check]
  <img width="388" height="336" alt="image" src="https://github.com/user-attachments/assets/9ee244b1-90a4-418f-a875-5c2a2367b980" />
  <img width="546" height="379" alt="image" src="https://github.com/user-attachments/assets/50a623f0-bb17-4d18-99a3-fe03f02a1016" />
  <img width="539" height="202" alt="image" src="https://github.com/user-attachments/assets/4def02a4-d319-4bff-b6b7-dfab268ac820" />




