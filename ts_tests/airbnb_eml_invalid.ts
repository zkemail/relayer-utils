export default `Delivered-To: dimitridumonet@gmail.com
Received: by 2002:a0c:fecd:0:b0:6c3:6081:347f with SMTP id z13csp81193qvs;
        Thu, 10 Oct 2024 16:19:45 -0700 (PDT)
X-Google-Smtp-Source: AGHT+IEd0XrzNnTswxWNTmEZgIArn+BlrkDF1vp1CyMewhYGmJAj19KVofiC8WRBHgTjYX7aQ6Cc
X-Received: by 2002:a05:6214:3b86:b0:6cb:e662:c59a with SMTP id 6a1803df08f44-6cbeff36cf0mr10369186d6.11.1728602385043;
        Thu, 10 Oct 2024 16:19:45 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1728602385; cv=none;
        d=google.com; s=arc-20240605;
        b=E0qFuaOfdPQc+Ld1vLPYWAZYD+jbI5AzUeQ/wL7UcJv1SSr0Pl4Ku+LBuzDOG+Gai+
         Pfn9ZHwXjMEFk/nZJw9RiXP3/c8y+0oi5dx4ojupMriS3WzsGB3r/T5+tLz7HDiMP8Zk
         f7zRkqEeCIY0OUJU/QMfxAdRmCUmE9TsqnKJ7e+Pf4Y1sIHwo0eoEGz0afHsizoaPOTJ
         KtUB0VYLLC/JmaPnpUZcD/biZRQgCsaL0XPLBvIK/URHnZniPM/hgB/9nQ24lJVX9/ZP
         tRT8yxnlmHDcfiauoSzVmBwC9Gh6+JFXoNC0mOkK1t7/RhPlSpPVj1RzhJHEwH+JPTn4
         EkvQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20240605;
        h=to:priority:importance:bimi-selector:reply-to:subject:message-id
         :mime-version:from:date:dkim-signature:dkim-signature;
        bh=qRjFxOyp02fNtl8fsqa9P9TfXf+KOCimKHiS6d8XZa8=;
        fh=wfDbold4LZmvpOGNo2jQk0a98jfSD+kr9vmhclYezSA=;
        b=ghyFgwCF/FyqVXrbUiiuPSa3Zu4yHwcLH6VIB/duhMOfiI3VTyV4QIduL41MfNnbg+
         gMe5x1JrkHdevne5zP1JRtR6cUPiyW2Rah6tXNsmxRPOJr2oqgq3SAorXRkLTX3VRoe9
         wv51uWUNGaVmfSS6mLmtmADlISwaV8Q47cusyUOnowVtvcAO3BtNnfMNUsR/eblplWiH
         VkuRbS61kqnnh8jL8Xj4LUj4lYvfhUPvwY6gGv2MET6OZu5+mdsr69RJ42mOIezZuDqy
         ZntooVCjbBCmRMKC3GzYq/tCJGtA5/EtGnd3PdZI+A0P/Z+WnTpH+HZZmgy0+XG/U38m
         GeWw==;
        dara=google.com
ARC-Authentication-Results: i=1; mx.google.com;
       dkim=pass header.i=@email.airbnb.com header.s=s20150428 header.b=i5GLT4zT;
       dkim=pass header.i=@sendgrid.info header.s=smtpapi header.b=D3G4ED+y;
       spf=pass (google.com: domain of bounces+168748-181c-dimitridumonet=gmail.com@email.airbnb.com designates 50.31.32.157 as permitted sender) smtp.mailfrom="bounces+168748-181c-dimitridumonet=gmail.com@email.airbnb.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=airbnb.com
Return-Path: <bounces+168748-181c-dimitridumonet=gmail.com@email.airbnb.com>
Received: from o11.email.airbnb.com (o11.email.airbnb.com. [50.31.32.157])
        by mx.google.com with ESMTPS id 6a1803df08f44-6cbe85e049asi24990216d6.161.2024.10.10.16.19.44
        for <dimitridumonet@gmail.com>
        (version=TLS1_3 cipher=TLS_AES_128_GCM_SHA256 bits=128/128);
        Thu, 10 Oct 2024 16:19:45 -0700 (PDT)
Received-SPF: pass (google.com: domain of bounces+168748-181c-dimitridumonet=gmail.com@email.airbnb.com designates 50.31.32.157 as permitted sender) client-ip=50.31.32.157;
Authentication-Results: mx.google.com;
       dkim=pass header.i=@email.airbnb.com header.s=s20150428 header.b=i5GLT4zT;
       dkim=pass header.i=@sendgrid.info header.s=smtpapi header.b=D3G4ED+y;
       spf=pass (google.com: domain of bounces+168748-181c-dimitridumonet=gmail.com@email.airbnb.com designates 50.31.32.157 as permitted sender) smtp.mailfrom="bounces+168748-181c-dimitridumonet=gmail.com@email.airbnb.com";
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=airbnb.com
DKIM-Signature: Invalid
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=sendgrid.info;
	h=content-type:from:mime-version:subject:reply-to:x-feedback-id:to:cc:
	content-type:from:subject:to;
	s=smtpapi; bh=qRjFxOyp02fNtl8fsqa9P9TfXf+KOCimKHiS6d8XZa8=;
	b=D3G4ED+yMdDJd90YTuhqvFdCDTfCU/cjAxBmB2MdDA9YquweURwttkoHraS02sYUznUK
	pg15OmQzP4WbAB2PRJAtSNF28FrZJOxs68ss7tEVAcF9YqHaYj6F5j/sMCZunhnr1aBJfY
	MMr8i8FPie9OlpKFcCG4y4VX0DtjHzBQ8=
Received: by recvd-fdb77b5cb-l2cqh with SMTP id recvd-fdb77b5cb-l2cqh-1-67086110-34
	2024-10-10 23:19:44.63636295 +0000 UTC m=+2438527.951122372
Received: from MTY4NzQ4 (unknown)
	by geopod-ismtpd-20 (SG) with HTTP
	id ozjDOM3PS6WltaTtjuJFaA
	Thu, 10 Oct 2024 23:19:44.626 +0000 (UTC)
Content-Type: multipart/alternative; boundary=49a8ec9b277e6a96e7373b3e4727df74d25ab6158dd0a8fb1221118a1304
Date: Thu, 10 Oct 2024 23:19:44 +0000 (UTC)
From: Airbnb <express@airbnb.com>
Mime-Version: 1.0
Message-ID: <ozjDOM3PS6WltaTtjuJFaA@geopod-ismtpd-20>
Subject: RE: Reservation at Luxurious 5B/3BA home Nob Hill! for 22 September
 2024 - 22 October 2024
Reply-To: "Isabella (Airbnb)"
	<4of5lutm2rzokajdtd2j25ek6whsg045r01d@reply.airbnb.com>
X-Priority: 1
X-Category: message
X-Strategy: push_and_email_and_web_push
X-rpcampaign: airbnb20241010152328760092722452715530303223890373903
X-Locale: en-GB
X-Message-Package-UUID: 7e892d74-33f4-ebf8-ef9a-cba7f9c2c579
BIMI-Selector: v=BIMI1; s=belov2;
X-User-ID: 467606067
X-MSMail-Priority: High
Return-Path: express@airbnb.com
Importance: high
Priority: Urgent
X-Template: homes_messaging/new_message
X-Feedback-ID: 168748:SG
X-SG-EID:
 =?us-ascii?Q?u001=2E373TPjtMqGbzwgRnUiLO4aQplIiW+Q7azdMrDCU1iICBGcf7GI8fS8Yas?=
 =?us-ascii?Q?=2FrvZ5srvc=2FUg+Y3QtuuZu8t9IoQj8U67X=2Ftferm?=
 =?us-ascii?Q?GqR0cRkWsdIQdo0l4Ezae3j01oY06yQrm91GBfs?=
 =?us-ascii?Q?5cx=2FNZOz3bvJt7R7OpkA=2FGLSMdeFwqzm9dhpSx8?=
 =?us-ascii?Q?YqLodw=2FoFKqS178kFLThUhL1OMuR7EJqMudXl81?=
 =?us-ascii?Q?Z1ab7TzKTs=2F1Ok7Pkf8CSI=3D?=
X-SG-ID:
 =?us-ascii?Q?u001=2ESdBcvi+Evd=2FbQef8eZF3BqZ9cHLZlaQH8LGBOs0K2+F024wgXfxgfZf8o?=
 =?us-ascii?Q?wozgZzIDr0SWjqkz0Hzl15He+3JiV4qiZ3NftmN?=
 =?us-ascii?Q?AQKXfQpNpidNvJalNic6JYjllxfNAmK52O3GlhD?=
 =?us-ascii?Q?FOjjI2YBmc2SQ5GYtyJGmycybZOQvvNcazI85yt?=
 =?us-ascii?Q?mPQq+Hz8fniF9EjPeVlfxQ0CoVMew0o+IUL9q46?=
 =?us-ascii?Q?+hi7Q+9jQAOPMZV=2FIZ4e3JazWnV58Av2FlUBtP0?=
 =?us-ascii?Q?yA=2F5kfOMtemfJB+3OWwPtttyQF8gCtEFp3cmd6m?=
 =?us-ascii?Q?39i+4FRprLKQypcH6HFCAg0WHbhyiK=2Fa+8ZWE5i?=
 =?us-ascii?Q?OTyPI3ajl5gFGwtrbgYnMTHOAERzqQMstiK3=2F=2F0?=
 =?us-ascii?Q?EpJEOMxvs8rkjoxbWnvEWjQMiJSyk+=2F2q6FDbow?=
 =?us-ascii?Q?s=2FGRpDmfjJeaiTN0jI8QLdDkHCWdfuPY5jnt8Xv?=
 =?us-ascii?Q?pX8cfwsbZpmoZflQ8PrIjcd=2FkxK7Gf4e5krU4Md?=
 =?us-ascii?Q?nzRx3=2FxRRYLEzocKrzMv=2FP1hpAC+RN7GKeKaosl?=
 =?us-ascii?Q?PD7zzN0jSqkzXnN1CKlcNYEygz0tPE=3D?=
To: dimitridumonet@gmail.com
X-Entity-ID: u001.xNm+654l4yZx3FKLl1hq6g==

--49a8ec9b277e6a96e7373b3e4727df74d25ab6158dd0a8fb1221118a1304
Content-Transfer-Encoding: quoted-printable
Content-Type: text/plain; charset=iso-8859-1
Mime-Version: 1.0

%opentrack%

https://www.airbnb.co.uk/?c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl&=
euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579

RE: RESERVATION AT LUXURIOUS 5B/3BA HOME NOB HILL! FOR 22
SEPTEMBER 2024 - 22 OCTOBER 2024

For your protection and safety, always communicate through
Airbnb
[https://www.airbnb.co.uk/help/article/209?c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5n=
L25ld19tZXNzYWdl&euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579].

   Isabella
  =20
   Hello guys! I need to let you know that the owner has
   scheduled a FaceTime tour with a long term group this
   Saturday at 1:30pm.
   I apologize for the inconvenience and
   Thank you for the cooperation.

Reply
[https://www.airbnb.co.uk/messaging/thread/1919382305?thread_type=3Dhome_bo=
oking&c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl&euid=3D7e892d74-33f4=
-ebf8-ef9a-cba7f9c2c579]

Respond to Isabella by replying directly to this email.

https://www.airbnb.co.uk/rooms/1193537369002070065?c=3D.pi80.pkaG9tZXNfbWVz=
c2FnaW5nL25ld19tZXNzYWdl&euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579

RESERVATION DETAILS

Luxurious 5B/3BA home Nob Hill!

Rental unit - Entire home/flat hosted by Isabella

GUESTS

10 guests

   CHECK-IN            CHECKOUT
                   =20
Sunday              Tuesday
                   =20
22 September 2024   22 October 2024

   https://www.airbnb.co.uk/external_link?c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL=
25ld19tZXNzYWdl&euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579&url=3Dhttps%3A%=
2F%2Fwww.facebook.com%2Fairbnb   https://www.airbnb.co.uk/external_link?c=
=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl&euid=3D7e892d74-33f4-ebf8-e=
f9a-cba7f9c2c579&url=3Dhttps%3A%2F%2Fwww.instagram.com%2Fairbnb   https://w=
ww.airbnb.co.uk/external_link?c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzY=
Wdl&euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579&url=3Dhttps%3A%2F%2Ftwitter=
.com%2FAirbnb

Airbnb Ireland UC

8 Hanover Quay

Dublin 2, Ireland

Get the Airbnb app

https://www.airbnb.co.uk/external_link?c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25l=
d19tZXNzYWdl&euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579&url=3Dhttps%3A%2F%=
2Fairbnb.sng.link%2FA6f9up%2Fdvs6%3F_smtype%3D3%26pcid%3D.pi80.pkaG9tZXNfbW=
Vzc2FnaW5nL25ld19tZXNzYWdl   https://www.airbnb.co.uk/external_link?c=3D.pi=
80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl&euid=3D7e892d74-33f4-ebf8-ef9a-cb=
a7f9c2c579&url=3Dhttps%3A%2F%2Fairbnb.sng.link%2FA6f9up%2Fqh0lc%3Fid%3Dcom.=
airbnb.android%26pcid%3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl  =20

Update your email preferences
[https://www.airbnb.co.uk/account-settings/notifications?c=3D.pi80.pkaG9tZX=
NfbWVzc2FnaW5nL25ld19tZXNzYWdl&euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579]
to choose which emails you get or unsubscribe
[https://www.airbnb.co.uk/account-settings/email-unsubscribe?email_type=3Df=
alse&mac=3DQJmdxe1CU5PXPvaEGjcsQ6TT5b4%3D&token=]
from this type of email.

=A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0=
 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0
--49a8ec9b277e6a96e7373b3e4727df74d25ab6158dd0a8fb1221118a1304
Content-Transfer-Encoding: quoted-printable
Content-Type: text/html; charset=iso-8859-1
Mime-Version: 1.0

<html lang=3D"en"><head><meta http-equiv=3D"Content-Type" content=3D"text/h=
tml; charset=3Dutf-8"><meta name=3D"viewport" content=3D"width=3Ddevice-wid=
th, initial-scale=3D1"><style type=3D"text/css">
@font-face {
  font-family: Cereal;
  src: url("https://a0.muscache.com/airbnb/static/airbnb-dls-web/build/font=
s/Airbnb_Cereal-Book-9a1c9cca9bb3d65fefa2aa487617805e.woff2") format("woff2=
"), url("https://a0.muscache.com/airbnb/static/airbnb-dls-web/build/fonts/A=
irbnb_Cereal-Book-aa38e86e3f98554f9f7053d7b713b4db.woff") format('woff');
  font-weight: normal;
  font-style: normal;
  font-display: swap;}
@font-face {
  font-family: Cereal;
  src: url("https://a0.muscache.com/airbnb/static/airbnb-dls-web/build/font=
s/Airbnb_Cereal-Medium-50fc004b3082375f12ff0cfb67bf8e56.woff2") format("wof=
f2"), url("https://a0.muscache.com/airbnb/static/airbnb-dls-web/build/fonts=
/Airbnb_Cereal-Medium-4bc8dafd2e0fd8914bf4d5edce9acd24.woff") format('woff'=
);
  font-weight: 500;
  font-style: normal;
  font-display: swap;}
@font-face {
  font-family: Cereal;
  src: url("https://a0.muscache.com/airbnb/static/airbnb-dls-web/build/font=
s/Airbnb_Cereal-Bold-bdfb98485e7836ba31b456f65cded088.woff2") format("woff2=
"), url("https://a0.muscache.com/airbnb/static/airbnb-dls-web/build/fonts/A=
irbnb_Cereal-Bold-a188841af78481a25b7bb2316a5f5716.woff") format('woff');
  font-weight: 700;
  font-style: normal;
  font-display: swap;}
</style><div><!--[if (mso)|(IE)]>
<style type=3D"text/css">
h1, h2, h3, h4, h5, h6, a, p, li, div, span {
  font-family: Cereal, Helvetica Neue, Helvetica, sans-serif !important;
}

a {
  color: #222222 !important;
}

h1, h2, h3, h4, h5, h6, a, p, li, div, span {
  color: #222222 !important;
}

.outlook-row-container {
  padding-bottom: 24px !important;
  padding-left: 48px !important;
  padding-right: 48px !important;
  padding-top: 24px !important;
}

a.base-button {
  border: 1px solid #222222 !important;
  color: #222222 !important;
  display: inline-block !important;
  font-size: 18px !important;
  font-weight: bold !important;
  padding-top: 16px !important;
}

a.embedded-button {
  border: 1px solid #222222 !important;
  color: #222222 !important;
  display: inline-block !important;
  font-size: 18px !important;
  font-weight: bold !important;
  padding-top: 8px !important;
}

div#brand-header {
  padding-bottom: 24px !important;
  padding-top: 48px !important;
}

.outlook-only {
  display: block !important;
}

.non-outlook-only {
  background-color: red;
  display: none !important;
  height: 0 !important;
  max-height: 0px !important;
  mso-hide: all !important;
  overflow: hidden !important;
  padding-bottom: 0 !important;
  width: 0 !important;
}
</style>
<![endif]--></div><style type=3D"text/css">
@media only screen and (max-width: 560px) {
  table .height_12_10 {
    height: 10px !important;
  }

  table .height_18_16 {
    height: 16px !important;
  }

  table .height_32_24 {
    height: 24px !important;
  }

  table .height_48_24 {
    height: 24px !important;
  }

  table .height_64_48 {
    height: 48px !important;
  }

  table .bottom_0_1 {
    padding-bottom: 8px !important;
  }

  table .bottom_1_1 {
    padding-bottom: 8px !important;
  }

  table .bottom_1_0 {
    padding-bottom: 0px !important;
  }

  table .bottom_3_2 {
    padding-bottom: 16px !important;
  }

  table .bottom_3_3 {
    padding-bottom: 24px !important;
  }

  table .bottom_4_2 {
    padding-bottom: 16px !important;
  }

  table .bottom_4_3 {
    padding-bottom: 24px !important;
  }

  table .bottom_5_3 {
    padding-bottom: 24px !important;
  }

  table .bottom_6_4 {
    padding-bottom: 32px !important;
  }

  table .left_0-5_0-25 {
    padding-left: 2px !important;
  }

  table .left_1-25_1-5 {
    padding-left: 12px !important;
  }

  table .left_2_0 {
    padding-left: 0px !important;
  }

  table .left_2_1-5 {
    padding-left: 12px !important;
  }

  table .left_3_2 {
    padding-left: 16px !important;
  }

  table .left_6_2 {
    padding-left: 16px !important;
  }

  table .left_6_3 {
    padding-left: 24px !important;
  }

  table .left_9_6 {
    padding-left: 48px !important;
  }

  table .right_0-5_0-25 {
    padding-right: 2px !important;
  }

  table .right_1_0 {
    padding-right: 0px !important;
  }

  table .right_1-25_1-5 {
    padding-right: 12px !important;
  }

  table .right_2_0 {
    padding-right: 0px !important;
  }

  table .right_3_2 {
    padding-right: 16px !important;
  }

  table .right_6_2 {
    padding-right: 16px !important;
  }

  table .right_6_3 {
    padding-right: 24px !important;
  }

  table .right_9_6 {
    padding-right: 48px !important;
  }

  table .top_0-5_1 {
    padding-top: 8px !important;
  }

  table .top_0-75_0-5 {
    padding-top: 4px !important;
  }

  table .top_0_3 {
    padding-top: 24px !important;
  }

  table .top_1_0 {
    padding-top: 0px !important;
  }

  table .top_1_0-5 {
    padding-top: 4px !important;
  }

  table .top_1-25_0-5 {
    padding-top: 4px !important;
  }

  table .top_1-5_0-5 {
    padding-top: 4px !important;
  }

  table .top_1-5_1 {
    padding-top: 8px !important;
  }

  table .top_1-5_1-5 {
    padding-top: 12px !important;
  }

  table .top_1-75_0-5 {
    padding-top: 4px !important;
  }

  table .top_1-75_1-25 {
    padding-top: 10px !important;
  }

  table .top_2_1 {
    padding-top: 8px !important;
  }

  table .top_2_1-25 {
    padding-top: 10px !important;
  }

  table .top_2-25_1-5 {
    padding-top: 12px;
  }

  table .top_2_3 {
    padding-top: 24px !important;
  }

  table .top_3_1 {
    padding-top: 8px !important;
  }

  table .top_3_2 {
    padding-top: 16px !important;
  }

  table .top_3_3 {
    padding-top: 24px !important;
  }

  table .top_4_2 {
    padding-top: 16px !important;
  }

  table .top_4_3 {
    padding-top: 24px !important;
  }

  table .top_6_4 {
    padding-top: 32px !important;
  }

  table .width_12_10 {
    width: 10px !important;
  }

  table .width_18_16 {
    width: 16px !important;
  }

  table .width_20_24 {
    width: 24px !important;
  }

  table .width_28_20 {
    width: 20px !important;
  }

  table .width_32_24 {
    width: 24px !important;
  }

  table .width_46_30 {
    width: 30.67px;
  }

  table .width_48_24 {
    width: 24px !important;
  }

  table .width_64_48 {
    width: 48px !important;
  }

  table .width_64_48 {
    width: 48px !important;
  }

  table .hide_small {
    display: block !important;
  }

  table .hide_large {
    display: none !important;
  }

  table a.base-button {
    display: block !important;
    font-size: 16px !important;
    line-height: 20px !important;
    padding: 14px 24px !important;
    font-weight: 500 !important;
  }

  table a.embedded-button {
    display: block !important;
    font-size: 14px !important;
    line-height: 18px !important;
    padding: 8px 14px !important;
  }

  table div.base-button-container {
    display: block !important;
    width: 100% !important;
  }

  table div.base-button-container,
table div.base-button-no-resize {
    font-size: 16px !important;
    line-height: 20px !important;
  }

  table .brand-header {
    padding-bottom: 0px !important;
    padding-top: 32px !important;
  }

  table a.header-nav {
    font-size: 12px !important;
  }

  table div.full-width {
    width: 100% !important;
  }

  table div.normal-container {
    border: none !important;
    border-radius: unset !important;
    overflow: visible !important;
  }

  table div.header-middle {
    background-color: transparent !important;
    border: none !important;
  }

  table div.header-bottom {
    border: none !important;
  }

  table div.hero-container-top-style {
    margin-top: 0px !important;
    border: none !important;
    border-radius: unset !important;
    overflow: visible !important;
  }

  table div.hero-container-bottom-style {
    margin-bottom: 0px !important;
    border-radius: 0px !important;
  }

  table .heading1 {
    font-size: 24px !important;
    line-height: 28px !important;
  }

  table .heading2 {
    font-size: 18px !important;
    line-height: 22px !important;
  }

  table .heading3 {
    font-size: 16px !important;
    line-height: 20px !important;
  }

  table .heading4 {
    font-size: 14px !important;
    line-height: 18px !important;
  }

  table h1.super1 {
    font-size: 32px !important;
    line-height: 36px !important;
  }

  table h1.super2,
table h2.super2 {
    font-size: 32px !important;
    line-height: 36px !important;
  }

  table p.heading-level-2-3 {
    font-size: 16px !important;
    line-height: 20px !important;
  }

  table p.heading-32-24 {
    font-size: 24px !important;
    line-height: 28px !important;
  }

  table p.medium {
    font-size: 16px !important;
    line-height: 22px !important;
  }

  table a.regular,
table p.regular,
table div.regular {
    font-size: 14px !important;
    line-height: 20px !important;
  }

  table a.small,
table p.small,
table div.small {
    font-size: 12px !important;
    line-height: 18px !important;
  }

  table p.ui-large,
table div.ui-large {
    font-size: 14px !important;
    line-height: 18px !important;
  }

  table p.ui-medium,
table div.ui-medium {
    font-size: 12px !important;
    line-height: 16px !important;
  }

  table p.ui-small,
table div.ui-small {
    font-size: 10px !important;
    line-height: 12px !important;
  }

  table p.ui-xlarge,
table div.ui-xlarge {
    font-size: 14px !important;
    line-height: 18px !important;
  }

  table p.ui-xxlarge,
table div.ui-xxlarge {
    font-size: 22px !important;
    line-height: 26px !important;
  }

  table a.x-small,
table p.x-small,
table div.x-small {
    font-size: 12px !important;
    line-height: 18px !important;
  }

  table td.cell-padding-bottom {
    padding-bottom: 24px !important;
  }

  table td.height_715_546 {
    height: 546px !important;
  }

  table.mobile-view,
table .mobile-view {
    display: table !important;
  }

  div.mobile-view-block,
div .mobile-view-block {
    display: block !important;
  }

  table.desktop-view,
table .desktop-view {
    display: none !important;
  }

  table.desktop-view-for-mobile-default,
table .desktop-view-for-mobile-default {
    display: none !important;
  }
}
@media only screen and (min-width: 561px) {
  table.desktop-view-for-mobile-default,
table .desktop-view-for-mobile-default {
    display: table !important;
  }

  table.mobile-view-for-mobile-default,
table .mobile-view-for-mobile-default {
    display: none;
  }
}
</style></head><body style=3D"margin:0 auto!important;padding:0" id=3D"body=
"><div style=3D"color:transparent;display:none !important;font-size:0px;hei=
ght:0;opacity:0;width:0"><img src=3D"http://email.airbnbmail.com/wf/open?up=
n=3Du001.Vf3ZgdAp00A3QHN2nFhKrXHWQkDjrh16-2FjWMP7Hvyx7LbdpEiaAyyUEa8Gi1g16a=
yyWindWxbL9mAGp82TklRR7x0BiPrhosSH-2FZvPEL1-2BVlaajMdo6DwoH7sUwGbXZQKS3HH2S=
BDfspaAY6KoVd7dbb-2BH-2FywR4sAzOhXk0uHD9O3o4lugtJLm1xHEdfMEjpS0uS3l-2BL6Srm=
Ohbyfr2uRlxRFTLb9jFAwQ1-2Fe96onsvwAlCj96RKxJE509H1yOg9ATIGwk1pvad5TGIuDCPiL=
lMBaNu1oozAIJ4SXVSD0VKwcO6lO819pAMaEyq6rvozA3S1x8OUbSYUz9T30Ch4DyiQI1Pbg7fe=
DgkHLRoNb6QHVUg5YWDQk6Ts62BZ5VfvOrLAKImCC-2B-2FAJjaeE3-2F4Q2wnEN2hUS81mZBxC=
l45LzAJOPVFgCtRbEyb2oQFU1sSACKmS0POdFvJqgbLox5x1OiTCkVAgGNfflVgBHYYWZ2h8oIS=
K-2Fa8kqrBVsfPwALle9mPbtxX3hwLa6rCjbKvf7lHaAwE0WKAogpbgUkJshnGfTazeYiSKpe3J=
xdhFA3qshB-2FVB0O23dVCnq-2Fwh5NwtqorYaMTIsZDBHFVhXVTwQE0K5dpViGFBottXS-2BmO=
SPQLMfxi9S7L09JdewpaFI-2FxaNg-2FXJZFuYyN7GJFaOM2zH86Hg70Hxt-2Bn6C3tWf3m7NB-=
2F398TYnmymoFWBexYJDGVXpw40t-2BjxX-2BLywbXbxeQ-3D" alt=3D"" width=3D"1" hei=
ght=3D"1" border=3D"0" style=3D"height:1px !important;width:1px !important;=
border-width:0 !important;margin-top:0 !important;margin-bottom:0 !importan=
t;margin-right:0 !important;margin-left:0 !important;padding-top:0 !importa=
nt;padding-bottom:0 !important;padding-right:0 !important;padding-left:0 !i=
mportant;"/></div><div id=3D"app"><div dir=3D"ltr"><table cellpadding=3D"0"=
 class=3D"_1vaxv5w" style=3D"max-width: 640px; border-collapse: collapse !i=
mportant; border-spacing: 0px !important; color: #222222 !important; displa=
y: table !important; font-family: Cereal, Helvetica Neue, Helvetica, sans-s=
erif !important; margin-left: auto !important; margin-right: auto !importan=
t; padding: 0px !important; position: relative !important; vertical-align: =
top !important; width: 100% !important;" role=3D"presentation" width=3D"100=
% !important" valign=3D"top !important"><tbody><tr class=3D"_16pg94n" style=
=3D"margin: 0px !important;"><td class><div class=3D"normal-container" styl=
e=3D"border: 1px solid #DDDDDD; border-radius: 12px; overflow: hidden;"><ta=
ble cellpadding=3D"0" class style=3D"border-collapse:collapse;border-spacin=
g:0;width:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=
=3D"margin: 0px !important;"><td class=3D"outlook-row-container left_6_2 ri=
ght_6_2" style=3D"padding-left: 48px; padding-right: 48px;"><table cellpadd=
ing=3D"0" class style=3D"border-collapse:collapse;border-spacing:0;width:10=
0%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0p=
x !important;"><td class=3D"brand-header" style=3D"padding-bottom: 24px; pa=
dding-top: 48px;"><a target=3D"_self" rel=3D"noreferrer" data-eon-role=3D"l=
ink" data-eon-prop=3D"href" href=3D"https://www.airbnb.co.uk/?c=3D.pi80.pka=
G9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl&amp;euid=3D7e892d74-33f4-ebf8-ef9a-cba7=
f9c2c579" class=3D"regular underline display-block" style=3D"font-family: C=
ereal, Helvetica Neue, Helvetica; font-size: 18px; line-height: 28px; heigh=
t: 40px; width: 104px; font-weight: 800; color: #222222; display: block !im=
portant; text-decoration: underline !important;"><img data-eon-role=3D"imag=
e" data-eon-prop=3D"src" alt=3D"Airbnb" src=3D"https://a0.muscache.com/pict=
ures/a6939621-d67c-4265-9762-55449eb5882c.jpg" style=3D"height: 40px; width=
: 104px; border: 0 !important;" width=3D"104" height=3D"40"></a></td></tr><=
/tbody></table></td></tr></tbody></table><table cellpadding=3D"0" class sty=
le=3D"border-collapse:collapse;border-spacing:0;width:100%" role=3D"present=
ation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td =
class=3D"outlook-row-container left_6_2 right_6_2 top_3_3" style=3D"padding=
-left: 48px; padding-right: 48px; padding-top: 24px;"><div><h1 class=3D"hea=
ding1" style=3D"font-size: 32px; line-height: 36px; color: #222222; font-fa=
mily: Cereal, Helvetica Neue, Helvetica, sans-serif; font-weight: 800; marg=
in: 0;">RE: Reservation at Luxurious 5B/3BA home Nob Hill! for 22 September=
 2024 - 22 October 2024</h1></div></td></tr></tbody></table><table cellpadd=
ing=3D"0" class style=3D"border-collapse:collapse;border-spacing:0;width:10=
0%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0p=
x !important;"><td class=3D"outlook-row-container left_6_2 right_6_2 top_3_=
3" style=3D"padding-left: 48px; padding-right: 48px; padding-top: 24px;"><p=
 class=3D"regular" style=3D"font-size: 18px; line-height: 28px; font-family=
: Cereal, Helvetica Neue, Helvetica, sans-serif; margin: 0 !important;">For=
 your protection and safety, <a target=3D"_self" rel=3D"noreferrer" data-eo=
n-role=3D"link" data-eon-prop=3D"href" href=3D"https://www.airbnb.co.uk/hel=
p/article/209?c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl&amp;euid=3D7=
e892d74-33f4-ebf8-ef9a-cba7f9c2c579" class=3D"regular underline" style=3D"f=
ont-family: Cereal, Helvetica Neue, Helvetica; font-size: 18px; line-height=
: 28px; font-weight: 800; color: #222222; text-decoration: underline !impor=
tant;">always communicate through Airbnb</a>.</p></td></tr></tbody></table>=
<table cellpadding=3D"0" class style=3D"border-collapse:collapse;border-spa=
cing:0;width:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" styl=
e=3D"margin: 0px !important;"><td style=3D"padding-left: 48px; padding-righ=
t: 48px; padding-bottom: 24px; padding-top: 24px;" class=3D"outlook-row-con=
tainer left_6_2 right_6_2"><div class=3D"_18j460n" style=3D"border-width: 1=
px !important; border-style: solid !important; border-color: #DDDDDD !impor=
tant; border-radius: 12px !important;"><table cellpadding=3D"0" class style=
=3D"border-collapse:collapse;border-spacing:0;width:100%" role=3D"presentat=
ion"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td cl=
ass=3D"left_3_2 right_3_2" style=3D"padding-left: 24px; padding-right: 24px=
;"><table cellpadding=3D"0" class style=3D"border-collapse:collapse;border-=
spacing:0;width:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" s=
tyle=3D"margin: 0px !important;"><td valign=3D"top" class=3D"height_64_48 w=
idth_64_48 bottom_3_2 right_3_2 top_3_3" style=3D"height: 64px; padding-bot=
tom: 24px; padding-right: 24px; padding-top: 24px; width: 64px;" width=3D"6=
4" height=3D"64"><img style=3D"height: 64px; width: 64px; border-radius: 50=
%; border: 0 !important;" alt=3D"Isabella" class=3D"height_64_48 width_64_4=
8" src=3D"https://a0.muscache.com/im/pictures/user/0d4ce48f-7f97-4b4f-aa27-=
8f4c513e0263.jpg?aki_policy=3Dprofile_medium" width=3D"64" height=3D"64"></=
td><td class=3D"top_3_3" style=3D"padding-top: 24px;"><table cellpadding=3D=
"0" class style=3D"border-collapse:collapse;border-spacing:0;width:100%" ro=
le=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !imp=
ortant;"><td class><div><p class=3D"heading-level-2-3" style=3D"font-size: =
22px; line-height: 26px; color: #222222; font-family: Cereal, Helvetica Neu=
e, Helvetica, sans-serif; font-weight: 800; margin: 0 !important;">Isabella=
</p></div></td></tr></tbody></table><table cellpadding=3D"0" class style=3D=
"border-collapse:collapse;border-spacing:0;width:100%" role=3D"presentation=
"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td class=
=3D"bottom_3_3 top_3_1" style=3D"padding-bottom: 24px; padding-top: 24px;">=
<div class=3D"regular" style=3D"font-size: 18px; line-height: 28px; margin:=
 0;"><p class=3D"regular" style=3D"font-size: 18px; line-height: 28px; font=
-family: Cereal, Helvetica Neue, Helvetica, sans-serif; margin: 0 !importan=
t;">Hello guys! I need to let you know that the owner has scheduled a FaceT=
ime tour with a long term group this Saturday at 1:30pm.<br>I apologize for=
 the inconvenience and<br>Thank you for the cooperation.</p></div></td></tr=
></tbody></table></td></tr></tbody></table></td></tr></tbody></table></div>=
</td></tr></tbody></table><table cellpadding=3D"0" class style=3D"border-co=
llapse:collapse;border-spacing:0;width:100%" role=3D"presentation"><tbody><=
tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td style=3D"paddin=
g-left: 48px; padding-right: 48px; padding-bottom: 24px;" class=3D"outlook-=
row-container left_6_2 right_6_2"><table cellpadding=3D"0" class=3D"_1cap30=
x" style=3D"border-collapse: collapse !important; width: 100% !important;" =
role=3D"presentation" width=3D"100% !important"><tbody><tr><td class=3D"_12=
to336" style=3D"text-align: center !important;" align=3D"center !important"=
><div class=3D"base-button-container full-width" style=3D"display: inline-b=
lock; font-size: 18px; line-height: 24px; background: linear-gradient(90deg=
, #E61E4D 1.83%, #E31C5F 50.07%, #D70466 96.34%); background-color: #FF385C=
; border-radius: 8px; font-family: Cereal, Helvetica Neue, Helvetica, sans-=
serif; font-weight: 500; text-align: center; width: 100% !important;"><a cl=
ass=3D"base-button " style=3D"font-family: Cereal, Helvetica Neue, Helvetic=
a; font-size: 18px; line-height: 24px; font-weight: 500; display: block; pa=
dding: 14px 0px; color: #FFFFFF; text-align: center; text-decoration: none;=
" data-eon-role=3D"button" data-eon-prop=3D"href" href=3D"https://www.airbn=
b.co.uk/messaging/thread/1919382305?thread_type=3Dhome_booking&amp;c=3D.pi8=
0.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl&amp;euid=3D7e892d74-33f4-ebf8-ef9a=
-cba7f9c2c579"><span class=3D"_vz5kef" style=3D"color: #FFFFFF !important;"=
>Reply</span></a></div></td></tr></tbody></table></td></tr></tbody></table>=
<table cellpadding=3D"0" class style=3D"border-collapse:collapse;border-spa=
cing:0;width:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" styl=
e=3D"margin: 0px !important;"><td class=3D"outlook-row-container bottom_3_2=
 left_6_2 right_6_2" style=3D"padding-bottom: 24px; padding-left: 48px; pad=
ding-right: 48px;"><p aria-hidden=3D"false" class=3D"ui-small" style=3D"fon=
t-size: 12px; line-height: 16px; font-family: Cereal, Helvetica Neue, Helve=
tica, sans-serif; margin: 0 !important;">Respond to Isabella by replying di=
rectly to this email.</p></td></tr></tbody></table><table cellpadding=3D"0"=
 class style=3D"border-collapse:collapse;border-spacing:0;width:100%" role=
=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !impor=
tant;"><td class=3D"outlook-row-container left_6_2 right_6_2" style=3D"padd=
ing-left: 48px; padding-right: 48px;"><a target=3D"_self" rel=3D"noreferrer=
" aria-label=3D"Go to listing details" data-eon-role=3D"link" data-eon-prop=
=3D"href" href=3D"https://www.airbnb.co.uk/rooms/1193537369002070065?c=3D.p=
i80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl&amp;euid=3D7e892d74-33f4-ebf8-ef=
9a-cba7f9c2c579" class style=3D"font-family: Cereal, Helvetica Neue, Helvet=
ica; font-weight: 800; color: #222222;"><div class=3D"non-outlook-only"><ta=
ble cellpadding=3D"0" class=3D"non-outlook-only" style=3D"border-collapse:c=
ollapse;border-spacing:0;width:100%;max-height:none;mso-hide:all" role=3D"p=
resentation"><tbody><tr><td background=3D"https://a0.muscache.com/im/pictur=
es/hosting/Hosting-U3RheVN1cHBseUxpc3Rpbmc6MTE5MzUzNzM2OTAwMjA3MDA2NQ%3D%3D=
/original/f395baea-883b-4326-b172-f91b49714ddc.jpeg" class=3D"_4dhvbds" dat=
a-eon-prop=3D"imageUrl" data-eon-role=3D"image" aria-label=3D"Luxurious 5B/=
3BA home Nob Hill!" role=3D"img" style=3D"padding-bottom: 56.2%; background=
-position: center; background-color: #F1F1F1; background-repeat: no-repeat =
!important; background-size: cover !important; height: 0px !important; max-=
height: 0px !important; overflow: hidden !important; width: 100% !important=
; border-radius: 12px !important;" width=3D"100% !important" height=3D"0 !i=
mportant" bgcolor=3D"#F1F1F1"></td></tr></tbody></table></div><table cellpa=
dding=3D"0" class style=3D"border-collapse:collapse;border-spacing:0;width:=
100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"margin: =
0px !important;"><td class=3D"outlook-only" style=3D"display: none;"><img a=
lt=3D"Luxurious 5B/3BA home Nob Hill!" src=3D"https://a0.muscache.com/im/pi=
ctures/hosting/Hosting-U3RheVN1cHBseUxpc3Rpbmc6MTE5MzUzNzM2OTAwMjA3MDA2NQ%3=
D%3D/original/f395baea-883b-4326-b172-f91b49714ddc.jpeg" style=3D"border: 0=
 !important;"></td></tr></tbody></table></a></td></tr></tbody></table><div =
class=3D"_6z3til" style=3D"overflow-wrap: break-word !important;"><table ce=
llpadding=3D"0" class style=3D"border-collapse:collapse;border-spacing:0;wi=
dth:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"marg=
in: 0px !important;"><td style=3D"padding-left: 48px; padding-right: 48px; =
padding-top: 24px;" class=3D"outlook-row-container left_6_2 right_6_2"></td=
></tr></tbody></table><table cellpadding=3D"0" class style=3D"border-collap=
se:collapse;border-spacing:0;width:100%" role=3D"presentation"><tbody><tr c=
lass=3D"_16pg94n" style=3D"margin: 0px !important;"><td style=3D"padding-to=
p:24px" class><table cellpadding=3D"0" class style=3D"border-collapse:colla=
pse;border-spacing:0;width:100%" role=3D"presentation"><tbody><tr class=3D"=
_16pg94n" style=3D"margin: 0px !important;"><td style=3D"padding-left: 48px=
; padding-right: 48px; padding-bottom: 8px;" class=3D"outlook-row-container=
 left_6_2 right_6_2"><div><h2 class=3D"heading2" style=3D"font-size: 22px; =
line-height: 26px; color: #222222; font-family: Cereal, Helvetica Neue, Hel=
vetica, sans-serif; font-weight: 800; margin: 0;">Reservation details</h2><=
/div></td></tr></tbody></table><table cellpadding=3D"0" class style=3D"bord=
er-collapse:collapse;border-spacing:0;width:100%" role=3D"presentation"><tb=
ody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td class=3D"o=
utlook-row-container left_6_2 right_6_2" style=3D"padding-left: 48px; paddi=
ng-right: 48px;"><p aria-hidden=3D"false" class=3D"ui-xlarge" style=3D"font=
-size: 18px; line-height: 24px; font-family: Cereal, Helvetica Neue, Helvet=
ica, sans-serif; margin: 0 !important;">Luxurious 5B/3BA home Nob Hill!</p>=
<p aria-hidden=3D"false" class=3D"ui-xlarge" style=3D"font-size: 18px; line=
-height: 24px; font-family: Cereal, Helvetica Neue, Helvetica, sans-serif; =
margin: 0 !important;">Rental unit - Entire home/flat hosted by Isabella</p=
></td></tr></tbody></table><table cellpadding=3D"0" class style=3D"border-c=
ollapse:collapse;border-spacing:0;width:100%" role=3D"presentation"><tbody>=
<tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td style=3D"paddi=
ng-left: 48px; padding-right: 48px; padding-bottom: 16px; padding-top: 24px=
;" class=3D"outlook-row-container left_6_2 right_6_2"><div><h3 class=3D"hea=
ding3" style=3D"font-size: 18px; line-height: 22px; color: #222222; font-fa=
mily: Cereal, Helvetica Neue, Helvetica, sans-serif; font-weight: 800; marg=
in: 0;">Guests</h3></div><p aria-hidden=3D"false" class=3D"ui-xlarge" style=
=3D"font-size: 18px; line-height: 24px; font-family: Cereal, Helvetica Neue=
, Helvetica, sans-serif; margin: 0 !important;">10 guests</p></td></tr></tb=
ody></table></td></tr></tbody></table><table cellpadding=3D"0" class style=
=3D"border-collapse:collapse;border-spacing:0;width:100%" role=3D"presentat=
ion"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td st=
yle=3D"padding-left: 48px; padding-right: 48px; padding-bottom: 24px;" clas=
s=3D"outlook-row-container left_6_2 right_6_2"><table cellpadding=3D"0" cla=
ss style=3D"border-collapse:collapse;border-spacing:0;width:100%" role=3D"p=
resentation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;=
"><td class><div class=3D"top_3_2" style=3D"padding-top: 24px;"><table cell=
padding=3D"0" class style=3D"border-collapse:collapse;border-spacing:0;widt=
h:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"margin=
: 0px !important;"><td style=3D"overflow:hidden" class><table cellpadding=
=3D"0" class style=3D"border-collapse:collapse;border-spacing:0;width:100%;=
table-layout:fixed" role=3D"presentation"><tbody><tr class=3D"_16pg94n" sty=
le=3D"margin: 0px !important;"><td valign=3D"top" width=3D"50%" class=3D"ce=
ll-left" style=3D"padding-right: 8px;"><div class=3D"_1mnp9e4" style=3D"bor=
der-width: 1px !important; border-style: solid !important; border-color: #D=
DDDDD !important; border-radius: 8px !important;"><div class=3D"_8jmbbt" st=
yle=3D"border-bottom: 1px solid #DDDDDD !important; padding: 16px !importan=
t; padding-top: 12px !important; padding-bottom: 12px !important;"><table c=
ellpadding=3D"0" class style=3D"border-collapse:collapse;border-spacing:0;w=
idth:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"mar=
gin: 0px !important;"><td style=3D"height: 12px; width: 12px; padding-right=
: 8px;" class=3D"width_12_10 height_12_10" width=3D"12" height=3D"12"><img =
alt class=3D"width_12_10 height_12_10" src=3D"https://a0.muscache.com/pictu=
res/44da4fa6-f192-46ed-a7af-f55174c286f1.jpg" style=3D"height: 12px; width:=
 12px; border: 0 !important;" width=3D"12" height=3D"12"></td><td class><h3=
 class=3D"_16pg94n" style=3D"margin: 0px !important;"><p aria-hidden=3D"fal=
se" class=3D"ui-small" style=3D"font-size: 12px; line-height: 16px; font-we=
ight: 800; font-family: Cereal, Helvetica Neue, Helvetica, sans-serif; marg=
in: 0 !important;">Check-In</p></h3></td></tr></tbody></table></div><div cl=
ass=3D"_1x0fg6n" style=3D"padding: 16px !important;"><div><p class=3D"headi=
ng-level-2-3" style=3D"font-size: 22px; line-height: 26px; color: #222222; =
font-family: Cereal, Helvetica Neue, Helvetica, sans-serif; font-weight: 80=
0; margin: 0 !important;">Sunday</p></div><table cellpadding=3D"0" class st=
yle=3D"border-collapse:collapse;border-spacing:0;width:100%" role=3D"presen=
tation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td=
 style=3D"padding-top:8px" class><p aria-hidden=3D"false" class=3D"ui-xlarg=
e" style=3D"font-size: 18px; line-height: 24px; font-family: Cereal, Helvet=
ica Neue, Helvetica, sans-serif; margin: 0 !important;">22 September 2024</=
p></td></tr></tbody></table></div></div></td><td valign=3D"top" width=3D"50=
%" class=3D"cell-right" style=3D"padding-left: 8px;"><div class=3D"_1mnp9e4=
" style=3D"border-width: 1px !important; border-style: solid !important; bo=
rder-color: #DDDDDD !important; border-radius: 8px !important;"><div class=
=3D"_8jmbbt" style=3D"border-bottom: 1px solid #DDDDDD !important; padding:=
 16px !important; padding-top: 12px !important; padding-bottom: 12px !impor=
tant;"><table cellpadding=3D"0" class style=3D"border-collapse:collapse;bor=
der-spacing:0;width:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94=
n" style=3D"margin: 0px !important;"><td style=3D"height: 12px; width: 12px=
; padding-right: 8px;" class=3D"width_12_10 height_12_10" width=3D"12" heig=
ht=3D"12"><img alt class=3D"width_12_10 height_12_10" src=3D"https://a0.mus=
cache.com/pictures/1167b82c-affb-4cbc-bfdc-efaa1542492f.jpg" style=3D"heigh=
t: 12px; width: 12px; border: 0 !important;" width=3D"12" height=3D"12"></t=
d><td class><h3 class=3D"_16pg94n" style=3D"margin: 0px !important;"><p ari=
a-hidden=3D"false" class=3D"ui-small" style=3D"font-size: 12px; line-height=
: 16px; font-weight: 800; font-family: Cereal, Helvetica Neue, Helvetica, s=
ans-serif; margin: 0 !important;">Checkout</p></h3></td></tr></tbody></tabl=
e></div><div class=3D"_1x0fg6n" style=3D"padding: 16px !important;"><div><p=
 class=3D"heading-level-2-3" style=3D"font-size: 22px; line-height: 26px; c=
olor: #222222; font-family: Cereal, Helvetica Neue, Helvetica, sans-serif; =
font-weight: 800; margin: 0 !important;">Tuesday</p></div><table cellpaddin=
g=3D"0" class style=3D"border-collapse:collapse;border-spacing:0;width:100%=
" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px =
!important;"><td style=3D"padding-top:8px" class><p aria-hidden=3D"false" c=
lass=3D"ui-xlarge" style=3D"font-size: 18px; line-height: 24px; font-family=
: Cereal, Helvetica Neue, Helvetica, sans-serif; margin: 0 !important;">22 =
October 2024</p></td></tr></tbody></table></div></div></td></tr></tbody></t=
able></td></tr></tbody></table></div></td></tr></tbody></table></td></tr></=
tbody></table></div><table cellpadding=3D"0" class style=3D"border-collapse=
:collapse;border-spacing:0;width:100%" role=3D"presentation"><tbody><tr cla=
ss=3D"_16pg94n" style=3D"margin: 0px !important;"><td style=3D"padding-left=
: 48px; padding-right: 48px; padding-top: 8px;" class=3D"outlook-row-contai=
ner left_6_2 right_6_2"><table width=3D"100%" role=3D"presentation"><tbody>=
<tr><td class=3D"_1rd2b9oa" style=3D"padding: 0px !important; border-top: 1=
px solid #DDDDDD !important;" width=3D"100%" role=3D"separator"></td></tr><=
/tbody></table></td></tr></tbody></table><table cellpadding=3D"0" class sty=
le=3D"border-collapse:collapse;border-spacing:0;width:100%" role=3D"present=
ation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td =
class><table cellpadding=3D"0" class style=3D"border-collapse:collapse;bord=
er-spacing:0;width:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n=
" style=3D"margin: 0px !important;"><td class=3D"outlook-row-container left=
_6_2 right_6_2" style=3D"padding-left: 48px; padding-right: 48px;"><table c=
ellpadding=3D"0" class style=3D"border-collapse:collapse;border-spacing:0;w=
idth:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"mar=
gin: 0px !important;"><td class=3D"bottom_4_3 top_4_3" style=3D"padding-bot=
tom: 32px; padding-top: 32px;"><table cellpadding=3D"0" class style=3D"bord=
er-collapse:collapse;border-spacing:0;width:100%" role=3D"presentation"><tb=
ody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td align=3D"l=
eft" width=3D"100%" class><img data-eon-role=3D"image" data-eon-prop=3D"src=
" alt=3D"Airbnb" src=3D"https://a0.muscache.com/pictures/d5e805e2-dfa8-4a7d=
-b06f-c5910be9a725.jpg" style=3D"height: 32px; width: 32px; border: 0 !impo=
rtant;" width=3D"32" height=3D"32"></td><td class><table cellpadding=3D"0" =
class style=3D"border-collapse:collapse;border-spacing:0;width:100%" role=
=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !impor=
tant;"><td class=3D"left_1-25_1-5" style=3D"padding-left: 10px;"><a target=
=3D"_self" rel=3D"noreferrer" data-eon-role=3D"link" data-eon-prop=3D"href"=
 href=3D"https://www.airbnb.co.uk/external_link?c=3D.pi80.pkaG9tZXNfbWVzc2F=
naW5nL25ld19tZXNzYWdl&amp;euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579&amp;u=
rl=3Dhttps%3A%2F%2Fwww.facebook.com%2Fairbnb" class=3D"regular underline" s=
tyle=3D"font-family: Cereal, Helvetica Neue, Helvetica; font-size: 18px; li=
ne-height: 28px; font-weight: 800; color: #222222; text-decoration: underli=
ne !important;"><img alt=3D"Facebook" src=3D"https://a0.muscache.com/pictur=
es/f6cf515c-976d-4a6a-a7be-1843301d6b14.jpg" class=3D"width_20_24" style=3D=
"width: 20px; border: 0 !important;" width=3D"20"></a></td><td class=3D"lef=
t_1-25_1-5" style=3D"padding-left: 10px;"><a target=3D"_self" rel=3D"norefe=
rrer" data-eon-role=3D"link" data-eon-prop=3D"href" href=3D"https://www.air=
bnb.co.uk/external_link?c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl&am=
p;euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579&amp;url=3Dhttps%3A%2F%2Fwww.i=
nstagram.com%2Fairbnb" class=3D"regular underline" style=3D"font-family: Ce=
real, Helvetica Neue, Helvetica; font-size: 18px; line-height: 28px; font-w=
eight: 800; color: #222222; text-decoration: underline !important;"><img al=
t=3D"Instagram" src=3D"https://a0.muscache.com/im/pictures/mediaverse/canva=
s-email/original/d98da6f9-52e5-47f8-9f15-134acfbf5e4b.png" class=3D"width_2=
0_24" style=3D"width: 20px; border: 0 !important;" width=3D"20"></a></td><t=
d class=3D"left_1-25_1-5" style=3D"padding-left: 10px;"><a target=3D"_self"=
 rel=3D"noreferrer" data-eon-role=3D"link" data-eon-prop=3D"href" href=3D"h=
ttps://www.airbnb.co.uk/external_link?c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld=
19tZXNzYWdl&amp;euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579&amp;url=3Dhttps=
%3A%2F%2Ftwitter.com%2FAirbnb" class=3D"regular underline" style=3D"font-fa=
mily: Cereal, Helvetica Neue, Helvetica; font-size: 18px; line-height: 28px=
; font-weight: 800; color: #222222; text-decoration: underline !important;"=
><img alt=3D"Twitter" src=3D"https://a0.muscache.com/im/pictures/mediaverse=
/canvas-email/original/126739e6-d2c8-47eb-82d5-c26299302f2f.png" class=3D"w=
idth_20_24" style=3D"width: 20px; border: 0 !important;" width=3D"20"></a><=
/td></tr></tbody></table></td></tr></tbody></table><table cellpadding=3D"0"=
 class style=3D"border-collapse:collapse;border-spacing:0;width:100%" role=
=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !impor=
tant;"><td style=3D"padding-top:24px" class><table cellpadding=3D"0" class =
style=3D"border-collapse:collapse;border-spacing:0;width:100%" role=3D"pres=
entation"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><=
td class><p class=3D"_jmqnks" style=3D"color: #222222 !important; font-fami=
ly: Cereal, Helvetica Neue, Helvetica, sans-serif !important; font-size: 14=
px !important; font-weight: 400 !important; line-height: 18px !important; m=
argin: 0px !important;">Airbnb Ireland UC</p></td></tr></tbody></table><tab=
le cellpadding=3D"0" class style=3D"border-collapse:collapse;border-spacing=
:0;width:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=3D=
"margin: 0px !important;"><td class><p class=3D"_jmqnks" style=3D"color: #2=
22222 !important; font-family: Cereal, Helvetica Neue, Helvetica, sans-seri=
f !important; font-size: 14px !important; font-weight: 400 !important; line=
-height: 18px !important; margin: 0px !important;">8 Hanover Quay</p></td><=
/tr></tbody></table><table cellpadding=3D"0" class style=3D"border-collapse=
:collapse;border-spacing:0;width:100%" role=3D"presentation"><tbody><tr cla=
ss=3D"_16pg94n" style=3D"margin: 0px !important;"><td class><p class=3D"_jm=
qnks" style=3D"color: #222222 !important; font-family: Cereal, Helvetica Ne=
ue, Helvetica, sans-serif !important; font-size: 14px !important; font-weig=
ht: 400 !important; line-height: 18px !important; margin: 0px !important;">=
Dublin 2, Ireland</p></td></tr></tbody></table></td></tr></tbody></table><t=
able cellpadding=3D"0" class style=3D"border-collapse:collapse;border-spaci=
ng:0;width:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n" style=
=3D"margin: 0px !important;"><td class=3D"top_4_3" style=3D"padding-top: 32=
px;"><table cellpadding=3D"0" class style=3D"border-collapse:collapse;borde=
r-spacing:0;width:100%" role=3D"presentation"><tbody><tr class=3D"_16pg94n"=
 style=3D"margin: 0px !important;"><td class><p class=3D"_1mzs5sdg" style=
=3D"color: #222222 !important; font-family: Cereal, Helvetica Neue, Helveti=
ca, sans-serif !important; font-size: 14px !important; line-height: 18px !i=
mportant; margin: 0px !important; font-weight: 800 !important;">Get the Air=
bnb app</p></td></tr></tbody></table><table cellpadding=3D"0" class style=
=3D"border-collapse:collapse;border-spacing:0;width:100%" role=3D"presentat=
ion"><tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td st=
yle=3D"padding-top:16px" class><table cellpadding=3D"0" class style=3D"bord=
er-collapse:collapse;border-spacing:0;width:100%" role=3D"presentation"><tb=
ody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td style=3D"p=
adding-left:0px" class><a target=3D"_blank" rel=3D"noreferrer" aria-label=
=3D"App Store" data-eon-role=3D"link" data-eon-prop=3D"href" href=3D"https:=
//www.airbnb.co.uk/external_link?c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZX=
NzYWdl&amp;euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579&amp;url=3Dhttps%3A%2=
F%2Fairbnb.sng.link%2FA6f9up%2Fdvs6%3F_smtype%3D3%26pcid%3D.pi80.pkaG9tZXNf=
bWVzc2FnaW5nL25ld19tZXNzYWdl" class=3D"regular underline" style=3D"font-fam=
ily: Cereal, Helvetica Neue, Helvetica; font-size: 18px; line-height: 28px;=
 font-weight: 800; color: #222222; text-decoration: underline !important;">=
<img alt=3D"App Store" height=3D"40" src=3D"https://a0.muscache.com/picture=
s/b34eaece-11bc-425b-956a-ee0fb1ab1501.jpg" width=3D"119.66" style=3D"borde=
r: 0 !important;"></a></td><td style=3D"padding-left:12px" class><a target=
=3D"_blank" rel=3D"noreferrer" aria-label=3D"Google Play" data-eon-role=3D"=
link" data-eon-prop=3D"href" href=3D"https://www.airbnb.co.uk/external_link=
?c=3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld19tZXNzYWdl&amp;euid=3D7e892d74-33f4-=
ebf8-ef9a-cba7f9c2c579&amp;url=3Dhttps%3A%2F%2Fairbnb.sng.link%2FA6f9up%2Fq=
h0lc%3Fid%3Dcom.airbnb.android%26pcid%3D.pi80.pkaG9tZXNfbWVzc2FnaW5nL25ld19=
tZXNzYWdl" class=3D"regular underline" style=3D"font-family: Cereal, Helvet=
ica Neue, Helvetica; font-size: 18px; line-height: 28px; font-weight: 800; =
color: #222222; text-decoration: underline !important;"><img alt=3D"Google =
Play" height=3D"40" src=3D"https://a0.muscache.com/pictures/8c1b684f-e6ed-4=
21d-9308-aa782c378d6e.jpg" width=3D"130" style=3D"border: 0 !important;"></=
a></td><td width=3D"50%" class></td></tr></tbody></table></td></tr></tbody>=
</table></td></tr></tbody></table><table cellpadding=3D"0" class style=3D"b=
order-collapse:collapse;border-spacing:0;width:100%" role=3D"presentation">=
<tbody><tr class=3D"_16pg94n" style=3D"margin: 0px !important;"><td class=
=3D"top_4_3" style=3D"padding-top: 32px;"><div class=3D"small" style=3D"fon=
t-size: 14px; line-height: 20px; margin: 0;"><p class=3D"small" style=3D"fo=
nt-size: 14px; line-height: 20px; font-family: Cereal, Helvetica Neue, Helv=
etica, sans-serif; margin: 0 !important;">Update your <a href=3D"https://ww=
w.airbnb.co.uk/account-settings/notifications?c=3D.pi80.pkaG9tZXNfbWVzc2Fna=
W5nL25ld19tZXNzYWdl&amp;euid=3D7e892d74-33f4-ebf8-ef9a-cba7f9c2c579" style=
=3D"font-family: Cereal, Helvetica Neue, Helvetica; font-weight: 500; color=
: #222222 !important;">email preferences</a> to choose which emails you get=
 or <a href=3D"https://www.airbnb.co.uk/account-settings/email-unsubscribe?=
email_type=3Dfalse&amp;mac=3DQJmdxe1CU5PXPvaEGjcsQ6TT5b4%3D&amp;token=" s=
tyle=3D"font-family: Cereal, Helvetica Neue, Helvetica; font-weight: 500; c=
olor: #222222 !important;">unsubscribe</a> from this type of email.</p></di=
v></td></tr></tbody></table></td></tr></tbody></table></td></tr></tbody></t=
able></td></tr></tbody></table></div></td></tr></tbody></table></div></div>=
<div style=3D"color:white;display:none !important;font:15px courier;line-he=
ight:0;white-space:nowrap">=A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =
=A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0 =A0</di=
v></body></html>
--49a8ec9b277e6a96e7373b3e4727df74d25ab6158dd0a8fb1221118a1304--
`;
