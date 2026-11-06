// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gcpkms

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/tink"

	kmspb "cloud.google.com/go/kms/apiv1/kmspb"  // injected by Copybara
	// Placeholder for internal proto import.
)

var verificationKeyMessage = []byte("data")

const (
	ecP256PEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEPu+j4MR6Veo9F2YyKq0AObMM3UoN
K4Z6V0tej/9smL+QfqkILtkY0DROmBbLb/tOg+zi/q6CAG5FuBK7CaZP0g==
-----END PUBLIC KEY-----`
	ecP256SignatureB64 = "MEUCIQD1n5HhsGwZ4hU2LVqTnUqQLlGidxPVVUBPbg8W1FGm4QIgQtSebi2H9/EZPKSsqYnkIFts" +
		"zI4jNZYWfcOFOjtJi7o="

	ecP384PEM = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEvhSzPPgaNlVa7ALdPv2TU/y7zcztJKMW
Uyb4EFljhW+HwMedJ9rq58P9vCO81GK+uzMElfKXwyh9Hwki3OrHw/U/QpEHrYAc
mjodwJBbZu8a/6Oc2bXN96IwqOhAM70l
-----END PUBLIC KEY-----`
	ecP384SignatureB64 = "MGUCMEJreAXQPgGuVKNEctuQRAh8sbdWbnxwbOIERx6A7KrXfx/VIGYsEIX9OjIgNGc+pwIxAOVN" +
		"n7DccgsZjhOwaL+HsI0RqbBFxRIaLQjlO9JT5BWxbsRX/7nio7krXpcfXFhnDg=="

	rsaPKCS12048PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnWdm/pltnPoPL7V+vQzI
YO0xm4d9lTBdWHWyvWIwFbG9ePPI2DS5bAUREY8pW/L7FzhHGvgrkuLgIFP8WTYd
4fm1L+QhhSIIltdnW8IeZobRsmrnz8oN/U6VPN8wGgPUzv1MM/vWQcNfDvv5E/kw
sJAD1e+V6S2rts2f8zFHHP71vXITSumOaVvJTVHZgyWEXA63C2MEQVMhzXrsnJua
5JY9TDAhFHDRiKzng9ZSbRmItutY8+FdlmoZVjWnFnhdloVvn/KzSjv0FmmHwmAI
Tt1aTrN7iWBoy/YBL61yxMMr91gtWh5Dp6KXYErYxS6v5fh5VOmrYJCeMugyokIW
zQIDAQAB
-----END PUBLIC KEY-----`
	rsaPKCS12048SignatureB64 = "NI2jo+WIrKjoyIR/jtlSBT0BJJJ0aDgIi86rXVOqPq35DyULjT1JwtKvgtqocNaeeKDQ4HRQhNKn" +
		"ZYeDzQO6nHD6SgngAv0v9FBGTph4VUNZ0To1Bzlk8LP+P/0PWWy59aAHzAFULCiU7/6nP2KSInbR" +
		"vg7UmMRXcfw956D3skFZn2dbu/xCRhYuZCiej72s6sNVRC1dHpIBz2+/f7ux4/gJgiYJGC9bvmkR" +
		"DzZIy7e3zf1Be7ZT/zAreAbL+Zk8BEvoWItV0YkDUs33MkFY1MCR44grai6fGGOJAxgahlcgvkue" +
		"O3tnao5epghHnwamS9I2h8zcBe984Z0MR+NXfw=="

	rsaPKCS13072PEM = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAi9Q2UorCOwp7Y5r+qO0n
mdlz8/GLQ1dh+9XR/wtL2uMGwEbTyziFt3UocxlxZLw6dQtHY3xfMW37lpRX5PFt
T68SeWRh+Cz+6i75NKa+FHrYM4d/HLYjFk+vOw75GIVfe0epi3UdMs5Ob8LGqaKP
PF6uPk/PSEJvXZ78Is2yODuUCecV0aDajQ/873jdwBrzXuaqG9SpLf8UTg891nuS
P+yZ075LvUu3ylcDxFsWclenATML3sgkrW1qQJKW5/UXRUQGNNnBPqF2EgIUlc6E
N8RszNjWKtzbs4EKirHd881Naw656nM/KfLj+00g0Vfd3/lvi2o8YFbDKcnKYZfI
tdohx9Zt4b3slCZOF/zMlvPKCn9tpa17A7rCBv57I80/+evKaq5PX84G+UcfV5kz
LHi+FNXBtJLzYr8JKxkad4U2ecjrK1jjvJtuPbqYosKCpRfBGsy3CdfeYn2xTtDZ
s+l73QYpWpnXUyjydhsTafQY0dce6azjrvmRWGFoSSRHAgMBAAE=
-----END PUBLIC KEY-----`
	rsaPKCS13072SignatureB64 = "iPyX74OCyZOh7GO7Y1UI3ucb8OMb9LoiIjHrW4jFKpS/aLjDGXrjEFbfsF3JITOFfOWx3M8+jIGs" +
		"4wwmHWiWCufqkbf4gtndGAoaEddeK2ph8tqXEnzkq8o5qDk175ffeZYmVI7/vi5xwc2oz5kd17wf" +
		"CD0MmFGxLef1C22Wz+MJTRi0LX6Ngsy/vR4Fx5N7+EXDdqPYx2ZLIhyQvXd7GztFxZTa8s7yQ6Gr" +
		"q2oslO13aMiu1dC9y9QYWLoY4uhF0te2WJerW5lRUp+00pk2ruC/yTaLXwS3bFZFx4FmNTClQCC/" +
		"JLugNekKJv9/FXex/L6muQseXxfezRiKV3fY2Ee7qxngZZZ/EU/TIDqBN3q3dE0eCyA/A2Ox7xtx" +
		"QqyTeIDeURZN9j5YtaVffp47oV2M0pSHTmcIyIwhHLx0MqWUPGUP3NvpjclNCeC5L8YieQKJiEBl" +
		"eoLpVA4nc2KEEdHyb+pFpaN+Pvw2V8X29uRl7ZIAkzxbnbaog7p3xza8"

	rsaPKCS14096SHA256PEM = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1GeEVEj1xv0ppPMAVMmK
PIsx7xt/6lyM2I9Am11HDVZ8+pN9FgGb7hMIXqBQWWhLCStvLBJPSlv+RUsw1GK4
3MD+Yxlc4X132KaC/Z6qIf+aD5FthfETtTEJem7HCTCSEyJXoeXYu69NrN9e+m+V
bcIVFaZ+f31tiDtSZi7fTCVbmSGG9WeqKZe/hKuhOan8lH2IJmxFjOk9hKFVqxB0
wTMFw7enAwLJxDqQMFXVK8zgjfvJ147AIol96VbS7si9Lnff9TfNjzcGfe1hsXNP
g10gLFu2N2LmjD9sb1gfWJGSGTsJiyX/owu+jj7GCWyQhY6hFTvZKbE0c1ZFLYbv
IiUBYJZUBk58iFgO7WA+fync9jDN9nNlw68e3xnqF7iherDS7IqZ5x8d+b+wgJKy
pBJI5hYY3OJB2yp4Ao9K4wQFxvJBBpg3jCGoofVVjrA8lePa3Yb8EHy+z5u5mYNj
VSxw8SXzqNsAgl5aW6c7Gs1c7m+Hpfdi4K+OJl60H0eYF+ks0KVShNRYri6q347D
IVpX3Qc6YOGPUHUj9lX7NfFJseGzbiJYTOQ+kVxvCmUqKMfq1vLvkgEfTpK53pTy
Z8h8oIZLTJo4MPwFbQAWNcKBGh43fMLWVWCED64N1S/2qNVv1R90OCerKLaX8WdY
txOSq3pgn5BD2tHhZ7ZmxTsCAwEAAQ==
-----END PUBLIC KEY-----`
	rsaPKCS14096SHA256SignatureB64 = "cqJsTB70moE9s+3OElRbmLFFXkRIYU0TKuhL+y8UMr/XUOqcXdrynnionthm6DJm681TJ88eHN29" +
		"eeZiyTt1UtQZBbMjAUOdrhcndHNdoxfQuVPJ8a4HuMOWXTT6B2ewxNDrWjhJZ2PARPBnl3OR1JWe" +
		"x8ynj7gIPFcsW6+pVDilMmxRkHHxj3xKplQ+uYRlY9ifggcs/ujx+UxZcScicfZWTbNuGlmddN6+" +
		"IV6q++gW7VoU+OZSaLBttFU93ohkLNnFYjRF1JxdKXNzOciJ7/AHtDd/XJ2zqnJsJCm0G/GkK+UB" +
		"W3lTkFcWjaqEqQEFKxVygIWIQsKF760BoZDkTgeSFeSo0aUAFG3WlKFoDQKQUVVgoKq0cU+VMqin" +
		"vfAunEHJAmq4An9IcxX3As8gyGByHO5xfoXwRrQfrJunRGWPvp5MXFm+i53FkfkDs1+DtypSKkX0" +
		"BrCSu1uRmIZxt0MhgJWgvQdXtglH3y4b7bmFOG/dvyGhMoSSpfRdjulPL/P5jW+zlDdwpr8WtrnY" +
		"RC0m4X8YpiBhXojYd1rtne5Q+A8t8EKNt2SXPadhSsRPoNF5wgD9tkoTvE0SbbdUm59c+cp9Hdj+" +
		"oJTWhYtpAcC+p6WebsZ9ILE180j44RRMF9GRk34AiDhr5bOwR+EEi8ScMj7LQhb+lcfQKwYr0EU="

	rsaPKCS14096SHA512PEM          = rsaPKCS14096SHA256PEM
	rsaPKCS14096SHA512SignatureB64 = "lq3wThF4Xa99ICz0vsTSBMa+uUclsECaUetUmLDvB/zjmHBIzeFrf6l0b/OtF9gnqq35nbvnJlaC" +
		"8vCZJMYfiGahkUfi7Vqw4sxxCfmBTbN+F8bl4n0dV+Na00pNHgRNKLaOcstyvBC74DD4e3mM799T" +
		"3nOELe8ASUCa0jGlVDhrSIQVt1wnfNZktrLWRjWm+cCz9w5RXira2fqz3/sDQbG6AcpJ8SzsfBd4" +
		"/52sQTRtrIDs2T+0BEku77rFozXMhO0ttkVsFijNsUr0R+FG3/gkPVBbMJl5ClCJw7qifsTsdw0M" +
		"iCunp6lvAm9CAz5AZMjA+iFgFSILaPLTFHy8Z5kFLcTqhgHcQAgqGGlhiucuuXruO+b907GyQ4tx" +
		"qWtWVuWmNWVgC9HAh3ra1tN7SgLj7cKFABq1GqNzkp6bDMtjutr8GfXMmIG/at4Uj9pmlpe+1ob1" +
		"dEFU8Oq/xdnrATTIzagqHrHqMSLqZ4/vXwwaDoIDDlR3tULV9/pPhh+60F4z8c4SbDSPOHTMxT3f" +
		"RtxO+ko9JZmka5PaGnjtNQVc16XYTR+23asReB6gcIu2xvvIhxtxASANdg5Nk+L/M6IZeFx0hnGO" +
		"B4AVQ2YF8IJ58A1rr9tT41MtyaPhGjOTNuFPlnyAJ5V/CalwuAtGFq5fMokC+AzcL4p9KruIodE="

	rsaPSS2048PEM          = rsaPKCS12048PEM
	rsaPSS2048SignatureB64 = "FhypcoCQT2X/9tn3qo7s9GSFjPew41hV2OveWlAwElYzke4dlfVIrpgnfpjOMHJuD2BIJc7ePKi2" +
		"XPTS+QS3LmWx8Qv4wKUgdluDK0ZD+Dm2MAHfYaLq3J3LqJhjOkcnM2KuYJcUFj40edYkhwg1oYUc" +
		"4EEKrSIh72Px6GGJa0nbRuCYx9vm7eH5zx/M4wIpOF+ScczoL6LkOyX8hFB2Ub9LxBh3OPahe/zT" +
		"QKy0+gMjUGqjwTxq3EBlkngY0LWh2fE+COhoq6mAddViyVfJjHCApY1KZXPWgg5tzbpttmDf6yKT" +
		"StTyAxt686GkeWL0kUzsmkGDQB1Ld6WJ+5KNlQ=="

	rsaPSS3072PEM          = rsaPKCS13072PEM
	rsaPSS3072SignatureB64 = "aM6ZNE2qRKuxc2Mdehc3Uju9eE8U4C9687M2keVOiHEeDCUo1uJJmBOPYJI8MM1h2G+KCMdy0006" +
		"zNuLGhANYASmplSCJfiI6eEJRhAgcX2km9VGeIF07VH+X0ZrdxTKX9hq4RnQL+NiAnhcDjmYfNF1" +
		"F+W86JjXt1QhWVPwCt0EhxC0dC41WyvM8a7r5e6P6VymkplCUuMIbnwNU4HtYyuc3HJnOgEODnrw" +
		"Z8jlNuHEHM0v7LEzYTcUXtmC/IhLYloxqOPVechEy0TZYC3Ir3rxa8JduTPCPnrYLsWRRUAchYIh" +
		"5eS+f4KHWSvZ8zPdjt18VouLTKZMhNRB/RlgV3SH8Ic3OVCoy979piJDyu9DGCRVZ5VoLH4Vuhkd" +
		"F5InvIzt7Lq5ApkF1JlKVM1V328ParbgGu0H+klCown/mD9sruFzJIzCat9wbX9gOMJAVSaZ6ZCK" +
		"XeLIF+aVe8kOxayniAulOzbK1xatXChSQk6vtg1egFu4XkwhI7C9IWDG"

	rsaPSS4096SHA256PEM          = rsaPKCS14096SHA256PEM
	rsaPSS4096SHA256SignatureB64 = "WMEq0q7+U24gx2SOwzWRI0M7aoYAvpQnz5kPMKRA4Ortn0bcJIsKXy4g4facoLygo+hJ4KiMmCQP" +
		"sbNoz/3hgfQcTc5XfPAVbkBkT3nnYcY77wib1f/VSQpdObcAs4bE7EyQrXUB4fkIdQlj96GvreP6" +
		"Vak0xjpSEdv0mA2rXuPWKsXUObsX1Wkto3Kz5DNplzxO2ofroo3VL8Lu3jv3OHH+c/fc9mKO5LRW" +
		"4nIaf6n8IkNq7zR2OioN3461+Uhc+5PpFBy9SCpdWJmlCYstN13Z8OLRi5zYhq8J8JBtJh1RkFDo" +
		"mNrEbkGKDd+VIgbuYpS7zRtJRFuBcHBrOorTLy84YWOW5xIn1HeWax/mPneUs+gJk4Eu7wGaFDyh" +
		"pJiLhw99AFn7b+Q2hCaQm+6/SW1YjBqKPX7Sd9JTjadsTO+t/3kEI31TN/2MTTAkTuRYswgm8dBs" +
		"RXmKMGJmzC7SIMxg0+tmuVkwbz2CPnv5CLSH9F6MuN1uynSWCzurOkyQUAy6J/A49EO/EPm+HY1W" +
		"F29Oz+3Hn++CDnBoB9fKorFWgqD0j6qwK6JDzT9e7Dn0Cp+EhbffU0BBYM0F6YgmbGN7Kf7XnrsY" +
		"ywVS6k6dmdkTzFWyRWszkfBNW3iTaOraGuEvQ8qi/93vNUFefGqDg0Mn7pm2bVL0Dukpc5RpRjg="

	rsaPSS4096SHA512PEM          = rsaPKCS14096SHA256PEM
	rsaPSS4096SHA512SignatureB64 = "zMztdsH/VYhGe32DCt3aSn9gUhzPREQhkMUi6bCHTzdV9wrN2yuAPCWRmBPymXh2tB7chB/gbJWU" +
		"YQeXYZtBgRnJKaPHhtQpeDFJwzbJt2eIiFA9RthLbo9kg1U9VuiXqfjKmkbj8Z5qbyJXVdl4f6hh" +
		"Ai2aGXaEpliRPLRUyuJRIIOU4O8clTQAoHqHCOLNtfpYU2LSABL6nM9awf/OGD98SFJ7sLwBDtB0" +
		"b7imZxBYayf0E1h1pza8XdHVYmTxQ+jdc5nYk+G27AzU0SZUviB5tdAt62xtFZiRi6vkk7FgfY+m" +
		"1jqv9FmklOiBuuZDPjdfQ1zlYTLdQHrGVCgO9jenC+OkeVyKOPmVgvETBsSEkr/W7kf2OM84mksy" +
		"mO10c0xqTCOi/cJd6zUYmi5IksU8DXQ1y8ZABzSoqIlRsOmyRQiW0CH+HmFl8HgtwZ9cSiKYtzag" +
		"I5QnFhvzpt3/fI52HeAebUFsd9x4xNmvcDkdXTO/cHCJXSRRO88LKBtuKZHgiXEfyQubEcTKMJxe" +
		"Q1sM0efzF/Br3aylzgzd+a5KvMq/0WGoVmHgvrH41lVxIlL2K1MHopfWz1Qi9sFVyB3MmIXIpcSL" +
		"GGYPgxL+zvqtZL+01ury1ASUw28414i4LU7OUO3C1oQc/tR4eETXYZ++qSsS6XmT7Br8k7h1VpQ="

	mldsa44PEM = `-----BEGIN PUBLIC KEY-----
MIIFMjALBglghkgBZQMEAxEDggUhAO34AyLWJzmaWTjHJYH/hMdN0tzFCG4MFLpI
ypwy9at0G3Putb3bJeLXI4Ypfj5PB96UK8B9GQfIvjI4No6cVpxE22qHqLZMEnIE
tK6eWrx9jYmwh8BLuTPUOAr7I/XWaKyZ3yJ8CbW7F95t2SrGQqc3+YcJHdPI33W4
tIeutKcaQ6BhbbB9Yu+Sf+OiNVyNeP+yuQvMdSbmjKNMnD1zi2sVf1je1Z9L4sWR
E7p7cPuEE2aSsXESz99TLJbOL/FjwsIDlcsOtGTd180ieL9Vx/mmNQ/jGJjEE1xP
XmhwAwBXtjvpd1ictZd0JihgIFDqg3Y574+0b1C5nqv1MURZ1ORJaEbp8AY+Ww+5
Ww0UWq/jprRw0bWIbHDxRdupypZ2C90y8GEc64qw/zDO16J6KGDAjIV8psHEeNZV
liaxnQRkYEvtIFwepzLy/5mirSRtV9qRInsuS9A5shACwf2o05pypTRBjMQkn8Jk
mcwv6fllgX4B8VaavFuQqf6DLlpoQ2DDXs7/HdR9zEGgwT7zIhSa7IR/0eZu3imI
COqhQVU3T8YRpnqt94C6moZ4pdnarrsqZVRRs4AR8L/waaukB+wKyzuh6fu1j69C
xnG9lgw5mXP31l4/01zWuLkizuZq+btG6BZhQuwpWQt69wAkqlxULRs3+KAXFGFx
m/3EooaiGuo28mK8AILQ6aY8QQu/Gva/0CCpAVHGPlqWKyawCcUl6zI47t+qzu+s
dK2PcjjQEKh5El06rKbR1yvpRUN1DjgRejCo475D2Mvh5QiXFupKVP713ND7IsJN
9dv894Qe/8tciVde0eRJJHXhcgcpVsmic8JJByCC7Z3iyeHeVTJ8DOcRhEy9J2di
wF5JA9OJoujOa9TZYWe6+0VenrWgP69EJ40tNYYkxK2f3BayxO7QMR/Q9K03NIC3
JAp7vMrvOTOzAF2vTIhj8ylS/SSXIWEr6q4lB8+gCn2hf1VOut2d/S6cug23pggL
IBC65P7bithq5fr25gj6regsERYP8qqu5dB6N6MB2l4T+IdAAzQqsDk1wonTnfvQ
fQ2ec3YlIl8+Kvj7so7VrNJLz9+MdcYvyG88FC1yWvHwNphsbjIze5BrwL0dexVF
G11OjtsFL9rGCJKsl8SmYrOF6m716Q/2+ySFU06mg9EhvSIZxcZofjBXEqo48LJP
OBCZBem8lWuMDC/yjBQoK9Dm3koRLY40Ffim+bXLdgaNuB3g8YiioKs8v3kcy1dS
RbpgEDCdHu6fygWczGUORnZ2+H5xWnQiTpOiX/5qKudFa+aNvmSolutPMAVUmNZN
WbBJ925hZHjNCVhfxnv7D9xSuzjY7oHXy+EkrUxrubwJZQeSG/Y4+MrrZtr6+kv7
xurKRCDbsmdwHebmjXCoRv+CVdBUoU74UQ92Xk70f78LQjoylYVVb+tYf3KoiDnT
XT3ZU0qTRhmIZ+vSMH5rNqYWvZDIkPFwKxWgFLcyXFS9FFB384aSSjYbh38/Wyyy
4BSazfBaCzhV2Sp7YJJtWSllyKbt+8DUO0/NxYykxd81Y5mT3EqxWjHYcdSUZpFY
dMplKPoJZrZjz2ksMXQ1s2Ydr40VKeOSlGx7pppcDc71lFDgn/a2rlteMRflwJRW
V7gFNosmQ06ol8FP/iCsHJ5MsODbf77lfClSX9wuN+96xpKw9scqLmNif+0ri0/O
FH02oJEQREKW+li7ydL1CNRMl1fQumIYxNypc71PhH5DzxLaPvg=
-----END PUBLIC KEY-----`
	mldsa44SignatureB64 = "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" +
		"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0TIS8="

	mldsa65PEM = `-----BEGIN PUBLIC KEY-----
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
M0+f519s
-----END PUBLIC KEY-----`
	mldsa65SignatureB64 = "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" +
		"GSAn"

	mldsa87PEM = `-----BEGIN PUBLIC KEY-----
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
Zz446F0LrThO+w2xfprlsmoy74I0Vw==
-----END PUBLIC KEY-----`
	mldsa87SignatureB64 = "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" +
		"AAALERgjKTE3PA=="

	ed25519PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEA3XaQHpiPZrQIYxDu3lpzU1SED8jho1/UD0/HkeKYXV0=
-----END PUBLIC KEY-----`
	ed25519SignatureB64 = "rLxQPAail7WmSyU8aDWvCwyZm/uDtj6DDrtNuyMPVADU7hzyFHv9NOT9tsMrtVITUEEuMCx9RUGY" +
		"p55VRNApAQ=="

	secp256k1PEM = `-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEuDj/ROW8F3vyEYnQdmCC/J2EMiaIf8l2
A3EQC37iCm/wyddb+6ezGmvKGXRJbutW3jVwcZVdg8Sxutqgshgy6Q==
-----END PUBLIC KEY-----`
)

type verificationKeyVector struct {
	algorithm    kmspb.CryptoKeyVersion_CryptoKeyVersionAlgorithm
	pem          string
	signatureB64 string
}

var verificationKeyVectors = []verificationKeyVector{
	{kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256, ecP256PEM, ecP256SignatureB64},
	{kmspb.CryptoKeyVersion_EC_SIGN_P384_SHA384, ecP384PEM, ecP384SignatureB64},
	{kmspb.CryptoKeyVersion_EC_SIGN_ED25519, ed25519PEM, ed25519SignatureB64},
	{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_2048_SHA256, rsaPKCS12048PEM, rsaPKCS12048SignatureB64},
	{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_3072_SHA256, rsaPKCS13072PEM, rsaPKCS13072SignatureB64},
	{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA256, rsaPKCS14096SHA256PEM, rsaPKCS14096SHA256SignatureB64},
	{kmspb.CryptoKeyVersion_RSA_SIGN_PKCS1_4096_SHA512, rsaPKCS14096SHA512PEM, rsaPKCS14096SHA512SignatureB64},
	{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_2048_SHA256, rsaPSS2048PEM, rsaPSS2048SignatureB64},
	{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256, rsaPSS3072PEM, rsaPSS3072SignatureB64},
	{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA256, rsaPSS4096SHA256PEM, rsaPSS4096SHA256SignatureB64},
	{kmspb.CryptoKeyVersion_RSA_SIGN_PSS_4096_SHA512, rsaPSS4096SHA512PEM, rsaPSS4096SHA512SignatureB64},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44, mldsa44PEM, mldsa44SignatureB64},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44_EXTERNAL_MU, mldsa44PEM, mldsa44SignatureB64},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65, mldsa65PEM, mldsa65SignatureB64},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_65_EXTERNAL_MU, mldsa65PEM, mldsa65SignatureB64},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87, mldsa87PEM, mldsa87SignatureB64},
	{kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_87_EXTERNAL_MU, mldsa87PEM, mldsa87SignatureB64},
}

func (v verificationKeyVector) verificationKey() VerificationKey {
	return VerificationKey{PublicKeyPEM: []byte(v.pem), Algorithm: v.algorithm}
}

func (v verificationKeyVector) signature(t *testing.T) []byte {
	t.Helper()
	sig, err := base64.StdEncoding.DecodeString(v.signatureB64)
	if err != nil {
		t.Fatalf("base64.StdEncoding.DecodeString(%v signature) err = %v, want nil", v.algorithm, err)
	}
	return sig
}

func newVerifier(t *testing.T, handle *keyset.Handle) tink.Verifier {
	t.Helper()
	verifier, err := signature.NewVerifier(handle)
	if err != nil {
		t.Fatalf("signature.NewVerifier(handle) err = %v, want nil", err)
	}
	return verifier
}

func assertVectorVerifies(t *testing.T, verifier tink.Verifier, vector verificationKeyVector) {
	t.Helper()
	sig := vector.signature(t)
	if err := verifier.Verify(sig, verificationKeyMessage); err != nil {
		t.Errorf("verifier.Verify(%v signature, data) err = %v, want nil", vector.algorithm, err)
	}
	corrupted := bytes.Clone(sig)
	corrupted[len(corrupted)/2] ^= 0x01
	if err := verifier.Verify(corrupted, verificationKeyMessage); err == nil {
		t.Errorf("verifier.Verify(corrupted %v signature, data) err = nil, want error", vector.algorithm)
	}
}

func TestNewPublicKeysetHandle_SingleKey(t *testing.T) {
	for _, vector := range verificationKeyVectors {
		t.Run(vector.algorithm.String(), func(t *testing.T) {
			handle, err := NewPublicKeysetHandle([]VerificationKey{vector.verificationKey()})
			if err != nil {
				t.Fatalf("NewPublicKeysetHandle(%v) err = %v, want nil", vector.algorithm, err)
			}
			assertVectorVerifies(t, newVerifier(t, handle), vector)
		})
	}
}

func TestNewPublicKeysetHandle_MultiKey(t *testing.T) {
	keys := make([]VerificationKey, 0, len(verificationKeyVectors))
	for _, vector := range verificationKeyVectors {
		keys = append(keys, vector.verificationKey())
	}
	handle, err := NewPublicKeysetHandle(keys)
	if err != nil {
		t.Fatalf("NewPublicKeysetHandle(all vectors) err = %v, want nil", err)
	}

	verifier := newVerifier(t, handle)
	for _, vector := range verificationKeyVectors {
		assertVectorVerifies(t, verifier, vector)
	}

	info := handle.KeysetInfo()
	if got, want := len(info.GetKeyInfo()), len(keys); got != want {
		t.Fatalf("len(KeysetInfo().KeyInfo) = %d, want %d", got, want)
	}
	if got, want := info.GetPrimaryKeyId(), info.GetKeyInfo()[0].GetKeyId(); got != want {
		t.Errorf("KeysetInfo().PrimaryKeyId = %d, want first key id %d", got, want)
	}
	seenIDs := make(map[uint32]bool)
	for i, keyInfo := range info.GetKeyInfo() {
		if seenIDs[keyInfo.GetKeyId()] {
			t.Errorf("key %d: id %d is not distinct", i, keyInfo.GetKeyId())
		}
		seenIDs[keyInfo.GetKeyId()] = true
		if got, want := keyInfo.GetStatus().String(), "ENABLED"; got != want {
			t.Errorf("key %d: status = %v, want %v", i, got, want)
		}
		if got, want := keyInfo.GetOutputPrefixType().String(), "RAW"; got != want {
			t.Errorf("key %d: output prefix type = %v, want %v", i, got, want)
		}
	}
}

func TestNewPublicKeysetHandle_Fails(t *testing.T) {
	goodKey := verificationKeyVectors[0].verificationKey()
	corruptedPEM := strings.Replace(ecP256PEM, "K4Z6V0tej", "AAAAAAAAA", 1)
	testcases := []struct {
		name    string
		keys    []VerificationKey
		wantErr string
	}{
		{
			name:    "empty list",
			keys:    nil,
			wantErr: "no verification keys",
		},
		{
			name: "slh-dsa",
			keys: []VerificationKey{goodKey, {
				PublicKeyPEM: []byte(ecP256PEM),
				Algorithm:    kmspb.CryptoKeyVersion_PQ_SIGN_SLH_DSA_SHA2_128S,
			}},
			wantErr: "PQ_SIGN_SLH_DSA_SHA2_128S",
		},
		{
			name: "hash slh-dsa",
			keys: []VerificationKey{goodKey, {
				PublicKeyPEM: []byte(ecP256PEM),
				Algorithm:    kmspb.CryptoKeyVersion_PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256,
			}},
			wantErr: "PQ_SIGN_HASH_SLH_DSA_SHA2_128S_SHA256",
		},
		{
			name: "raw rsa pkcs1",
			keys: []VerificationKey{{
				PublicKeyPEM: []byte(rsaPKCS12048PEM),
				Algorithm:    kmspb.CryptoKeyVersion_RSA_SIGN_RAW_PKCS1_2048,
			}},
			wantErr: "RSA_SIGN_RAW_PKCS1_2048",
		},
		{
			name: "secp256k1",
			keys: []VerificationKey{{
				PublicKeyPEM: []byte(secp256k1PEM),
				Algorithm:    kmspb.CryptoKeyVersion_EC_SIGN_SECP256K1_SHA256,
			}},
			wantErr: "EC_SIGN_SECP256K1_SHA256",
		},
		{
			name: "unspecified algorithm",
			keys: []VerificationKey{{
				PublicKeyPEM: []byte(ecP256PEM),
				Algorithm:    kmspb.CryptoKeyVersion_CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED,
			}},
			wantErr: "CRYPTO_KEY_VERSION_ALGORITHM_UNSPECIFIED",
		},
		{
			name: "rsa pem with ecdsa algorithm",
			keys: []VerificationKey{{
				PublicKeyPEM: []byte(rsaPKCS12048PEM),
				Algorithm:    kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			}},
			wantErr: "not an ECDSA key",
		},
		{
			name: "p384 pem with p256 algorithm",
			keys: []VerificationKey{{
				PublicKeyPEM: []byte(ecP384PEM),
				Algorithm:    kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			}},
			wantErr: "EC_SIGN_P256_SHA256",
		},
		{
			name: "2048-bit rsa pem with 3072 algorithm",
			keys: []VerificationKey{{
				PublicKeyPEM: []byte(rsaPKCS12048PEM),
				Algorithm:    kmspb.CryptoKeyVersion_RSA_SIGN_PSS_3072_SHA256,
			}},
			wantErr: "modulus",
		},
		{
			name: "ml-dsa-65 pem with ml-dsa-44 algorithm",
			keys: []VerificationKey{{
				PublicKeyPEM: []byte(mldsa65PEM),
				Algorithm:    kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44,
			}},
			wantErr: "does not match",
		},
		{
			name: "ed25519 pem with ecdsa algorithm",
			keys: []VerificationKey{{
				PublicKeyPEM: []byte(ed25519PEM),
				Algorithm:    kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			}},
			wantErr: "not an ECDSA key",
		},
		{
			name: "ecdsa pem with ed25519 algorithm",
			keys: []VerificationKey{{
				PublicKeyPEM: []byte(ecP256PEM),
				Algorithm:    kmspb.CryptoKeyVersion_EC_SIGN_ED25519,
			}},
			wantErr: "not an Ed25519 key",
		},
		{
			name: "corrupted pem body",
			keys: []VerificationKey{goodKey, {
				PublicKeyPEM: []byte(corruptedPEM),
				Algorithm:    kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			}},
			wantErr: "EC_SIGN_P256_SHA256",
		},
		{
			name: "not pem",
			keys: []VerificationKey{goodKey, {
				PublicKeyPEM: []byte("not a valid pem"),
				Algorithm:    kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
			}},
			wantErr: "failed to decode PEM",
		},
		{
			name: "not pem with ml-dsa algorithm",
			keys: []VerificationKey{{
				PublicKeyPEM: []byte("not a valid pem"),
				Algorithm:    kmspb.CryptoKeyVersion_PQ_SIGN_ML_DSA_44,
			}},
			wantErr: "failed to decode PEM",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			handle, err := NewPublicKeysetHandle(tc.keys)
			if err == nil {
				t.Fatalf("NewPublicKeysetHandle() = %v, want error", handle)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("NewPublicKeysetHandle() error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
