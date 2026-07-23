using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using TameMyCerts.Enums;
using TameMyCerts.Models;
using TameMyCerts.Validators;
using Xunit;

namespace TameMyCerts.Tests;

public class CertificateRequestValidatorTests
{
    private readonly ITestOutputHelper _output;
    private readonly CertificateRequestPolicy _policy;
    private readonly string _request;
    private readonly string _request_mldsa44;
    private readonly string _request_mldsa65;
    private readonly string _request_mldsa87;
    private readonly CertificateTemplate _template;
    private readonly CertificateRequestValidator _validator = new();


    public CertificateRequestValidatorTests(ITestOutputHelper output)
    {
        _output = output;

        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        _request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDbTCCAlUCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApucZpFuF0+fvdL5C3jggO6vO\n" +
            "9PA39MnPG0VQBy1n2pdhD/WwIt3St6UuMTXyNzEqSqm396Dw6+1iLCcP4DioLywd\n" +
            "9rVHOAFmYNeahM24rYk9z+8rgx5a4GhtK6uSXD87aNDwz7l+QCnjapZu1bqfe/s+\n" +
            "Wzo3e/jiSNIUUiY6/DQnHcZpPn/nBruLih0muZFWCevIRwu/w05DMrX9KTKax06l\n" +
            "TJw+bQshKasiVDDW+0K5eDzvLu7cS6/Z9vVYHD7gGJNmX+YaJY+JS9tGaGyvDUiV\n" +
            "ww+Do5S8p13dXqY/xwMngkq3kkvTB8hstxE1pd07OQojZ1SaLFEyh3pX7abXMQID\n" +
            "AQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkqhkiG9w0B\n" +
            "CQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUsp05C4spRvndIOKWrM7O\n" +
            "aXVZLCUwPgYJKwYBBAGCNxUUMTEwLwIBBQwKb3R0aS1vdHRlbAwOT1RUSS1PVFRF\n" +
            "TFx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4ATQBp\n" +
            "AGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABv\n" +
            "AHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJKoZIhvcNAQELBQADggEB\n" +
            "ABCVBVb7DJjiDP5SbSpw08nvrwnx5kiQ21xR7AJmtSYPLmsmC7uIPxk8Jsq1hDUO\n" +
            "e2adcbMup6QY7GJGuc4OWhiaisKAeZB7Tcy5SEZIWe85DlkxEgLVFB9opmf+V3fA\n" +
            "d/ZtYS0J7MPg6F9UEra30T3CcHlH5Y8NlMtaZmqjfXyw2C5YkahEfSmk2WVaZiSf\n" +
            "8edZDjIw5eRZY/9QMi2JEcmSbq0DImiP4ou46aQ0U5iRGSNX+armMIhGJ1ycDXTM\n" +
            "SBDUN6qWGioX8NHTlUmebLijw3zSFMnIuYWhXF7FZ1IKMPySzVmquvBAjzT4kWSw\n" +
            "0bAr5OaOzHm7POogsgE8J1Y=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        // ML-DSA:44 Key
        // CN=intranet.adcslabor.de
        _request_mldsa44 =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIQADCCBnYCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIF\n" +
            "MjALBglghkgBZQMEAxEDggUhAGJTvnrMRe9aoA256EjAocVC9QUezjyqxVz0rUgF\n" +
            "3HyP0SmvmUGKpfDYNZTT0v0//Uoavzecg6P/LOWwKr6TJ9mIOD/5B8jrX/z79wz6\n" +
            "MW+ngwobYXH1TyIoSOUjAnCfoN5NrSiXqO7RPYL/IhFroWsWbFyjTm5W0MRu1oLu\n" +
            "O9jCFsP7gQm2oTO+5jzI24Y++uqBZvF0nhrd9AvjKNwzkk85KJu7qDn+TQT+ivGu\n" +
            "GP7Izk4cAzDq7XoYdCsemNmDEVDZD0s9pwybrAACp3D2ZCpOEkvlX87U0kZJkAhW\n" +
            "qGuA6KI0aJYtYBK6q4GBLPMLML8Eh/LtvAuNAO3hIEBFR2yLeNAENafuI/H93Nfl\n" +
            "97gRYm3cYcG8JVAMY2lHJv6ZT9jlypRs6eHydSwid+e6tIXvwuW1OL/Hm87X9f6P\n" +
            "gMRsUesykwqHfmON8wYlnn2kbHdC+oZWG0V8OkOl5BF02XLMkHA+3SbfypGGPXUu\n" +
            "sCm2BI0rJ4XJaseMbfoUv310jeKnHW1cyEjLnCikHoooWlFimvxJuWhvBMLnGU5f\n" +
            "IFoQHkm9cC9rJCf/aMhmi067EYfuyVwgBWsrWSIlIDheGQ4oQiT/CbS3WCE9scq6\n" +
            "KPgFn6uMoqGeCA1d/9G6/hp4cz/yIbrfeaoOjE3dAgviTgDQzHCRbb5KZrB0e+du\n" +
            "whLQogaE2oBet2t3h/ywOTQPLFc+NIoJATn1dx7zI0bztj+eLeXXCiM2Tbz8Wn8v\n" +
            "HRUDopAZmnLABmZKbiA8Htc5mGoEU3yNLAFdogpInAcMctdeVuRt5KPEbr/4Mw+Z\n" +
            "vouuAu52BNR6oeklTCNYuKueoIDeegvW7QkS9THQpYzAQkWTjNdhXyXmD8tHMOQa\n" +
            "UIcDw0BuQ+c/fBfN+Ui6xubrNe3aO7BWwdfvG8ew9QY/RmjPCeprTeyqr0IETeUL\n" +
            "5m4JKjNPSplvgpEC+B/3QWoK2aYLNxZH4A+ut3x0Xd8bkqP5QhRmoLFBXRBV/yor\n" +
            "EXlFMljRvfbXm9M8enP8YMg2eJijuGlOtkRmc+Getgnu+laSFbpN9pwDlw7mAPBL\n" +
            "hu2QhatNNG/BQVPlxI/wWjHKfZxw8hi2HMTufcoEdfrTxCaiug2LBDGz1USdjNDg\n" +
            "C5yRazgG/izyHbYCpq5B6/lkC80N2x1c+8pkeNLVNohe134tVjTp/uBPggHoJryn\n" +
            "3qsbI/iZ9NZtIHEi22SKCQ1f7BCrU0xkkjHRsnFeunSSNW/ensfoAXlonoZYtFT+\n" +
            "1Y9isk66yt8jKczR3Tsr2VYfGDtELFhu/LcK06Ohm4+hkkvYCANTNEQoFEtB9j0s\n" +
            "cyyhq/hJbkBTV94cNYacR6wA/jVvsgMhkmb1+0VrBYJpH8lWnPGhuwVrsjvoV4FJ\n" +
            "yqVeGEkne8g2g4bbzi75ipTF1ii+CjGOwCMWcygqe9HvUh+nn0YXm2C8VaFfmkN3\n" +
            "RjqN+Yf5tjtQff055cBURAcaP+AmQ1UIwDVlJwQdf+y8JHfwf49YvcidpT3erPR/\n" +
            "yRhS0y5C3MhZx9rccrtwUoQAdPQo+6Gpem/LKybCeRyX/LAMxE8vlAdX8Kq3xewj\n" +
            "DFY9GhMoEYJ24il9jmGlYDWpZhtzWRiHHHCadzYCMEnegGzMY66h1lbzYE6BNOOQ\n" +
            "gwiOl27i77faF7u9V+9p93JaDc0+idecuRSOkO0QWK7D5WAFlBzcjrN3KPh10kyd\n" +
            "kOKPMPwaB80fTaKX84O2dAuxT3U2+AWHDJoiZXRDDJmNpT+gggEXMBwGCisGAQQB\n" +
            "gjcNAgMxDhYMMTAuMC4yNjEwMC4yMD4GCSqGSIb3DQEJDjExMC8wDgYDVR0PAQH/\n" +
            "BAQDAgeAMB0GA1UdDgQWBBTzzNymxz97blt0RJTBprKrhzAyZzBPBgkrBgEEAYI3\n" +
            "FRQxQjBAAgEFDBZQQzAxLmludHJhLnBxY2xhYm9yLmRlDBNJTlRSQVxBZG1pbmlz\n" +
            "dHJhdG9yDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0A\n" +
            "aQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQA\n" +
            "bwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMAsGCWCGSAFlAwQDEQOCCXUA\n" +
            "mLL8wQwD0Y19GdUrcxz9fqJRY/F3f6w1tZL1gX+Y2eGUIvb4OPRQKAfMIXUOgBS1\n" +
            "2aTuEwBRMEH6c39kxuRJQeCpYAEAWx2Q2E03BRGtM57TWHUd9z7kGlfcLkx3eeww\n" +
            "A4yz/Z49J/SwxXEpbxtv7hsIRal3AG8toM15KXgdtGzLx1/mhsFYe9H10gAXfzgX\n" +
            "EI4xfRBNL2okf9vlC25cL7Qu4lPNp0caEP9byb/MKpC5pxe24ksA60VYzgWjkgc2\n" +
            "JORD0xz8VmR3XXxe4h875Ar3AjMjQ6C+eGFFTPwBL2F/e7RuuNDbLcQolPjk3Tur\n" +
            "rcG++RmZ7UuC0EctSH7m48/jQ+KqiT4PbFknJXmJVGMzs/XyW1Xop8vAwwZEWjkw\n" +
            "rxsW4a6M8qUIPzLRaypdsdSUW+rEg31FoWMzcJuUSqQ5NKwh0Eq181DBdMFnCS3W\n" +
            "z2srKbTWOYzFcLUe+QPclyZdt4kgATwZES7cnqMd7z/SlzZslTZqqyOVONOQ6t4V\n" +
            "bhkvrTWPMVIYFRFxIL/lUuq2MAp0hHcA1rgRFoNOJhJw4ayemPk4Nr9FZ2BQsQeu\n" +
            "rZC5ESLRlYFaadb3uSqk+g4CEg4rL8JF59I8hZibmeX2rtClwOCpQn53wNMYGx/V\n" +
            "JR+hdg3kz63BywAMz23KA0/yDtiWjMbBp3pwkf9q0aT/+6l8Kbjfc5SuWrWwZMFt\n" +
            "auHWQwbrk8+IAzHxsBaj6IpDor9+4Ek92BcsFdkazDcqflA+/EKZJCgcu2FB1dmD\n" +
            "rJ2kbelCaRX2z5iXUY/vBpwi06+Sqh6JHmGP9QyiHw2+Obso5LGXJEfFCEEnXvOH\n" +
            "7yKLtEGOPfTeQIgtkI7ROTaAhALLYBBMGaCvonMLdfkX1nK81GJvF+lFgYyIHuYW\n" +
            "glTwb1jphq0PaRv6n5mmPrH7qY+yc1SfHaht6lmxKEIqcgFBIUR1usvE6kXm8Uip\n" +
            "WooDzrPnghQitIC/BFKFc6WHgGYRQiYYe77dLWz9CLFV0TexK45HTsOpBpXGY4MW\n" +
            "8kEC7R6X9zzaw9Di7fgNiFjklRo0qsEKrknrVP+P9V09HwFxoZ2qnisfSPGJ8BZd\n" +
            "6nZmt6/MypP2SbYcEl9+go497wjlcGAIaYQLdJ+DC9AN7rSJ3cLK/UfkMliZc8Ye\n" +
            "z/F+jAtspJFIoJvYN/ll5mW4k8up6uKorJRCw8vX8bkQD31NKsOfKfFgiAsCujba\n" +
            "1OrY6SlFT8hQMjP1N0CK6DvpTOZrbFfeQKQihDByxzqDNGnoSucQs9PJpLQdV16h\n" +
            "LE7q4SkTDqgkRSDADw7sgaJuqabkg2FSdXmoSJR23Qd5xt/b+leAq6dLRIHJLmUG\n" +
            "jcKDMrQAQ+fJGi1qoSkVkaDPlHUba+LfRP3TsMBA5gk9VRsmgZkNp1wwGBxxB4Fh\n" +
            "Dw97stIEg5P2FOlN148xvkYF/2SSbiRqi05R4+O5zAuX5A5qyN/ZtT69siraTQzw\n" +
            "9z/vcIR4NcznxFaCjTUwCmqPbAYNCYQFNmJNeQzbuSLSGfarqc3UYu8Gs7cT4Rvv\n" +
            "arTPh06uUtRcGXynFkYd8S6F3LnSIh5v14l9mHcOBunIgWWik1y+pbviSGzgtXRr\n" +
            "5aF5rSL33MFB5QWo/4PquwjpaS+XNDRXqyhNLxT2h9Vj4Az+LCiURlvbl041meie\n" +
            "F6Imj/aczf9kL5wkZDJed/Raww/tkM2GamOOKU3yHLZTkxBlWU6DVKvb2lnEqJDo\n" +
            "M4sGKtQI3nYVqLLRnkvozByF7Ty+0xzWvsjVWvOZWSp4yZDN8VTPBHVmQctkSSVD\n" +
            "ypA2hp17UruDrvoea4rE1L8Yot4opgBQ/4FDn2LvPanTxlpiTMEt3s/UwjmV4zZG\n" +
            "QDTV9UdwbHMh04LRyGvK5HrNBx+R5LZJV9JKWazhAtvpmCWkTY2mNqk+vRTyzEf7\n" +
            "ffxXZ/oi1suXpCXvtzfPiLVRDr2yfdZKf2jTNE/awaMh45x+CdYZ7SKdnsnfo0F9\n" +
            "v1+e7DLo86GTQ8eLKFFI7RXdpdli+PpvbVHhxhj6kAkBnELJzW8TCXwbN7jY38DH\n" +
            "Uarmg/PbqXAHgviuN4f65tqAp94q/KK2HRtDoRa/VGWaFwdvctDXZoXl2xuQdAzS\n" +
            "vJ7qs/Hm5P7xc+6tBP3/FKbJE49xmoN9aT1y6x/I47F6gOVikCTqqDE5oKdOCPzr\n" +
            "nV2bn73Vsfqy5ENzZco7X/UCYnEZ1EexnIwSvA9xQ7Sqzzvf2a7TOTFW85xNRFWY\n" +
            "OzNBFQoDhka8osaJEhkz5Y+AEZmUMPBfjOGeSAOxHkDxueXpTqi32jeTjJ4yNTdR\n" +
            "rfqHsoo1lmVgzP1M7ScJ8HSzaU6iUnFQ3RW341ZoVem5rPfDRJk2Bmjs6NzvA8RE\n" +
            "qEvkxMxDhae3jD4wASCexTLjjgLlMZQpaBpuxK5SAaxZVmKZ8H/5b3QNPVRQe81P\n" +
            "SK0CoCBOd5qmUOVLSpZUw9iAL285IqJPLlarsKMu30gpjN6dyiP/OjoaDkew8vQs\n" +
            "yqcWU/qO5dEGrVSx3uEbA10JmUzlLps3nIGk52vCnq2CrzFRsC5Cby67SUYR5Hx9\n" +
            "l+MFNSjv0084vuhn6hmK0nDlSOYBfeviFVKm1EEb1CL92ZD5vPvKchHUW2olWmCu\n" +
            "L239QbKHPfdQr7crOsenIEUVYHxDjKkpJCxN9koItn8WiFihCBHFjxQcOqkOn3BR\n" +
            "tmQmQrDQNzb7U+z7+gWwLWzcAMvExN53LSO27bcDDi0DI+vkGjb7wtn+nVr4/rJZ\n" +
            "3P5q0/1klLS3ALWb7NqDqNuqSHpR9bvyP5BbD2Cev44d3m20fSa0CzfxmadJfa34\n" +
            "b72c5phgeYGV64NRGJLs7AOKVe06Fc6rs9e0e2gTyWaU/kZN0/DSTk8pjjBTffPE\n" +
            "HNdw+/ENUuIlNz0BR+74n6Hh+LP/U/2+8UBNZArvBYhsr2JFKOkQWAtcKPoqhwbP\n" +
            "MPKshJmJ7XtrXqLNJXHYx3cmsQFBoEqnlp5wLywJJvvDCMBg/6Y7qorB/16LKvTV\n" +
            "Hoa1uP3S5w9+GGJCoypDXWPXWGNQOITXcnbELneeoX/QYJ7FtDXpu0bLw+EaPF3w\n" +
            "sMQiDZX49AEOmiHj7p1gYDu9eaea5Rgv1ilfKESPGy4hM1BWWVxwgIyoytLdAURQ\n" +
            "Z3iHjZucwez5/BMcICNWaYWetNLTGR0zUlZidZOcuMvV1vn7/wAAAAAAAAAAAAAA\n" +
            "AAAAAAAAAAAAAAAAAAAAAA0aJTU=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        // ML-DSA:65 Key
        // CN=intranet.adcslabor.de
        _request_mldsa65 =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIV+TCCCPYCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIH\n" +
            "sjALBglghkgBZQMEAxIDggehAM6uWxYpOc9hlD4+9d6uh1UOrOq7cxukuL5S0Dt0\n" +
            "SDwJ8wQQfYypa46+x0m3zR+prnYb6XJm+2Enk55RJsTJB6k9QvL9um6JNfw02zHm\n" +
            "Oea9Lt1ibw+9VPOdsUYZr4A/0Ar7hHK6++PrqKP5hfwUmCUx1E4oWQAJbmTDAZv3\n" +
            "OergWM6IsjLoEM6/X4QwPXTU7qoSyNxVIv7+BzSomXDBziEOKp46S/rA1BsNQywQ\n" +
            "9WJ/1xSqkSYorxzOO8MBdWp/xykamEbnXtjbopMXCMEaWS8biZihSs1gNe1K6C0t\n" +
            "GFhqJnDYvXx/AogudrAMduBg3IZLWnYU+CQ/TybZoNuX4vUYVEDpAJ9cLTL88mdf\n" +
            "MaqWR6iD57AFlz81nAoXCrazmCWtuBIACA2OoIPa5An2vIFtaTU0EdxsQtsVil2y\n" +
            "o7pmjqwbVpoVAsKx+7cCVZ/0gUW2mXZ+u0KXacLkQDRw896qEpUCc6gbVJX8M18p\n" +
            "Lk0qUOLlPl1IX9KMHt1WNCfhx295bwiowqC2+cjGM7w5ZzmdT0bsdATdmWttVhsn\n" +
            "A5rT8mtE2xXjXziBePR7hZaVwiOB0gCyzBZXGHQLeQYPac201p9bVFEzLif9CAd0\n" +
            "QDr+w1YxD+8O4FolbTNh+4bkv5emXun7g8grKlgdrbaGef+sV1J3MvzyDjb3s9x5\n" +
            "3dLnsTNZMi9uO4torDnaI7Gtw6Er/FTF+mlSAUYIp8JtNNnxydfYDKNmDgXhnScI\n" +
            "7vJVx1nRfnqlnt2sUWAuAC7+2Q303Ikrpm/k8T5D6kwtXb9VBJdsavpDRokyQ9la\n" +
            "E7TbF2uxRU7ZF/P6Fkq5OpKhKxjbPIdCG3hoO1TFqn5e8SOZsmX8F/nY8dl9KPVA\n" +
            "Bp+u81W+AzTRge+e67cDNB4tuD/OLB3h4stkHik0RCqw7G5GqiEgbfFndn1X/eZy\n" +
            "J4yT89E7REzQE1ubdQ2bo76oRLLfI32Lwa1GTdleTsJ/hPDMALZ0484hzUY7lzAD\n" +
            "BRyFvpfeFa71w9bSk6t4hpozQnOkgukW716G8Ja6xzn9wpdJUEyTeGLkrgtddyuo\n" +
            "lKLcsKVgIcDDuRSywwTUCy9rVjDK83LgoWTieltJ5piilSa8WNwSrvt8gwIp99+7\n" +
            "Mx9gm7unl8nmgPelt2koMU7Vf7hmuUHMHbG8YLTLhcDw7ykltyAGtwei4drsm3HV\n" +
            "GOh37MwwkKqH3Fiv4isOqdZFVCSIq4qjkObq200pYalyL6R+tnR+aso7nNoa//4N\n" +
            "3leRw2a+rM+8QgPoLWsFtdV0wIajrgVkLKv9xvvgIpNJoMEoj/OJuUROAwzKNi3u\n" +
            "3Fyi7NDjQZk5MRjfNRK1ZK071qNjMTiWC4dagz1+2FPDcfFNDc2Um5uxvN0d+4dc\n" +
            "6DHOynCly34jiOslcEDy2//omQT7JON4+oNvdY8S6FC/td5Ey/aUm/2t66M6EXUr\n" +
            "CiQrIrzlretYIDSITwurA92hR0zIi4THBlJTpDuOnnFg8gNsky658FlidKbf42jE\n" +
            "hxB8MgMSUozUrPVdlxdrYvmH2QxE5z19OLxqw6Ifr1yJWoPA4HhnxFje8uflkAhZ\n" +
            "d8ZNZhZ4hGDH0vNRD5f1CSKD3NZ6ziXuhGO/+3NV/fkgX7vCBDZFjfV4vF/Bbh67\n" +
            "Q1amyuam9hJw2laX7PF/yam/2hgyGbTeG+h1W7MgOPNAJ2T3qs1KHKLvI2puNlO7\n" +
            "NNQwcwZjPUrKph8mcucyVGqNkgVBvgkD+EDKaJVgLEmvsIo71r/b4q2kVDVuLvLQ\n" +
            "cg2u3cOh8eyiUFA2aVx/ZOsdzqrSdh+k1qB1qtt6GZFQ0d/vDWNvgTDPYNvYsm5G\n" +
            "ExHxtfoMs9By1pTS9kYwV5jGL7+I1Uy6n6WYU6TH4NvlVrGAGdvkuc2zu/UqmcOV\n" +
            "ev6mIzGG/LZVhTcO1uhf/Sdm1WxZx7tEb8PsEGZrSgEmSSMusKG54gqCZg3Z0eGv\n" +
            "nZEEl+4psXTTpb5RfbYsOyU43KddvUw6gsu2eejTHkxuUjjMmczaqLUAtiHY6Hgx\n" +
            "48d/nkiiig0l7N5K+siMIO1Es3w+gJ1wsFOB0IZ7UInsJrA8Uk66JAOVbqmf1C6d\n" +
            "P1ZZLwbirPJaQuobN3bmxHjdqn1Ot0pHCu6f88AoH03DNZILGWaywgKD+1kaYF9Y\n" +
            "xKFhibarOozgIG9uAzBPg0jJvN1yQ9sNrUQA/4HXzzdLaRORBy4wUpiEoxKcPimV\n" +
            "xm0eJ1f2DK+HXSpZhHdw4ic7qgntUwiTiE07lYB82+ucZ63M4zTndBjQFEEPItQv\n" +
            "7cJfRZllxpL5Y5xt4lTiV7GdOi8hTdHMnEgXaLZpzLwrR4NTkTaotTf1irYNglt3\n" +
            "62w7N/AIF9fyfxbyHawTg0ayfth0m7vR0ao/PFnd7vkOYNqlcSto22eLpYINwU66\n" +
            "TtvG0dz9xjgyY9+tUKIrv506SwwxocV1R+9OddvWkj5YnTiEVYueeicma25rwzQ6\n" +
            "TORIUqW85Gcc9bW90x2dxDcRLRS5zJl2fyVOtJTqrpEEnJWYM1PWqjRM/fs/ve26\n" +
            "UUwErlClCMxcjJARbjwGOm4fxdcGXUFooqvhuPvbwdp+8cStGmSp5U7twRL+GIKA\n" +
            "15RPoIIBFzAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMjYxMDAuMjA+BgkqhkiG9w0B\n" +
            "CQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUa3DYXu6bQ5P0wna+rN8v\n" +
            "c4BH81MwTwYJKwYBBAGCNxUUMUIwQAIBBQwWUEMwMS5pbnRyYS5wcWNsYWJvci5k\n" +
            "ZQwTSU5UUkFcQWRtaW5pc3RyYXRvcgwOcG93ZXJzaGVsbC5leGUwZgYKKwYBBAGC\n" +
            "Nw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBhAHIA\n" +
            "ZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMBADAL\n" +
            "BglghkgBZQMEAxIDggzuAHAyCfTYdAQBElvFPzqqAi37EmwQpdH2p+AoPxtfRL20\n" +
            "7G6zsUbuD3vuM199XkSb1/k2Wced+VguSngffEDtQVWR9RcElUo1P7xokh5aROhs\n" +
            "fNC0T4llWrT/D8qs/5VU4re9UUOpgc0T8Sbeb4u/faJieUK8i5rxkWc1uXpHzT4K\n" +
            "o5rYKIv3YO7+m0JCk8oGmkY/7q+hMTl6fLndEC6PMNB0Ck3z3lee9kydkNwHQH9t\n" +
            "FPBijMWzgTFat3CGrDOJIeYT8KzeExI4IgTL1TPqNCLEb0l+p3BAWsLeM5IwBXJm\n" +
            "ycruskPtGJJ9UA5NdKxXBSJdiTwK7DlAaUi+5jVM7XWFr5Z0FxUknnrwhdB3508p\n" +
            "TWK5JzttLg0XKxbNl9FNZHqp5XKy4QdqYVFMBs0JE6Vlqgm7bkGvrW0Qk0mPSv0G\n" +
            "7Zt7GdVSTB8+vvjqZfU2F2ZQYaLa5n5zPospoEjd5K1w+L3sZYeu8V8T4B0Vid97\n" +
            "dJA9/STwoOf2o32gMH45uGyMHxRdny87TSC47uYPh98/PGack1u/cI8ORA9aY/Ej\n" +
            "0aOgtc/KSggorDjXf5iG13xgXl44Z7cqL0RlilE2/YMcDnS5fLOqlbxUbrKOBjS/\n" +
            "x96PBL8bDQibxUMOlQ7IfSj6Knx75IclBYVMEI77dy8eBeq2q15rwSq1XV73qzHJ\n" +
            "CvKZmfM+b0k5U731YuYK5Hep3KwwC/c2wCKWJQ/5U2qembFXg9uLS2e/tDP/8Uig\n" +
            "kDspwcgzsJR9feYYm8d/RIGwM7cZEpMsiUcxRpTmO8vyOg8SENvm2l5P4uC/ujJS\n" +
            "QDgaOrmL6wtd9AQDW4Qe0xSaM9ZXCscKYVShRXy0O0tv4BDK+sazoPToE5boEFP6\n" +
            "3vlLUJwEvvbMAywbpLBnwm/e/eQGny02xRfsBP6/s9zQRlNv69DVrnwRLS9RTDQf\n" +
            "PF81nqrcEiwL2FkrGy1RiV+eySMhZVN2r2cdsYYmMF0fwEyftMSuBfj95BhvpHIN\n" +
            "TNoLTBEKapSeRe1fSNEn5jCjraZ95e+brhK6a4PMMCZ+Ds1DGCncp/0RgjWAtuwT\n" +
            "vtUKkyUSNiSUx6KYEvXz+gkpNwf5y23SN/34i3N06C2T/FVzRVVFxmXTOiwq9ckG\n" +
            "5f0ZoZCbVyFCk2slPL1b699VbOpm6lxddM0MMRfZZcNkGdVxyozTYyFitoPaE3GJ\n" +
            "/FHPJIIYDq2wGI2vJ7lHSzGJROmH1DYGtjjpS+JXo4gxTiEffG32eBttGuC4tgGK\n" +
            "efMwLAccX1KYVzHBf2THiT4h9ynH7V3CSPIS2pHb71kLXX4diLDShzWPsUzq2/HC\n" +
            "3pkT8Ioil8OAq52LSF5xot3AHYPNVBEbrCSzYCDuG7XJFKQuOUTgqrnHkjUkqOo0\n" +
            "JwZwsWEdwHSV3BFJ8HtI1XOPP1cxwZd6387L8Hb9MrCamFFIEakCNzCUE4n4UkIu\n" +
            "1XOAXZ49mz0xaeXygm/N6/jvTHdC4P30rX4ER1JRf6iGbDmFa1k/wqAqTwNghvL8\n" +
            "SZqUsEDikchBq8pOwigTb27D2e9cIVZQUlj5r+aVE+W0w8gOPqRv8bD8bab2kYN1\n" +
            "BOWTKXYebFsTY5xwsjbH+32R5Pc7G0cRLRwspsXfW3aQ2ZnkBjLFSWa40es3b9SL\n" +
            "3D3B60IBAiuaeF6jZMiyyQLMjTQFMQL/K0SPwI3Wvi0LtizEzFiQtxbQbYMGFgBo\n" +
            "rl/HrqEfPlzMxESvkd/NyLAJU7Uu9+fcw4Z0ZlnFQDB4wbY+Kc6+ezdcsOlaQLLM\n" +
            "yZGy+LSL91MT8isuhJhZfR4KtnfFuMog/yKv33m8rknIQCV1ocZSrsMzrX7/Dq63\n" +
            "7/nFW8g1tsRFoNN/lQJvVY1KhKbtfX5J8hJBhx3sxTzNAMLi8dRrxeHthUuogQ2o\n" +
            "u0T5AMBY+5O6plxziOMuHSxS7GZT0YzHHkf8Nz74aMEHBoIfY/MpUWYBUoUSEgln\n" +
            "ed9ZK9gZLCiilPxAfgf2T7Yv1hm5zVNoy2LTEbad6qudx4CxeW9hxamy/b5dk/fc\n" +
            "j4tlOdivJ24F3XyY/U2c1N9WsyICV0Bx+6SW9gpYL+M/mwycEKF1VU2tPAT3+bUf\n" +
            "wUDNuINw73BHtI8SHt2yL9iejSNDixN+NehvFD+W3xapbjL9cfFvDmjSnGSWBqZK\n" +
            "Nu4pMq5p6TeLdz/yUqXyvC7BDH84OyyKtBGKSaISBYRLfIOS+F8SeTd2i01ehr75\n" +
            "URKj9x8z38w9vMoNLRfBcw8JBpi+HmnnISa8Nu6U37Md7WJfv6WMtw7mSgtUg3hY\n" +
            "6azvWaHFOcQn38K0aYaRjtG5DW6+QVX6UODz/LG54uFeAwwneacKslBZZaIqpnG7\n" +
            "9dn3GZKlzqFoa9BMI9Hsods3dgY5+sfb6/VMWkAyIP1yrE0P2qScmJNOJyfFHEiY\n" +
            "emcbpugYM1N3zUP1rh0BDyS1adQ39sFigWW1yxBLrAo3/M453WEOVKyZQrFriXZn\n" +
            "L6NuimnSTh87YREDUwKxVt6YDMO/CRJksPaEzCfOtvEQyhNgeHnqxW4/wHl+FH8z\n" +
            "U00DHTR8PlIZ+FR1zw6RdE+ShLJC8HZHAn1tmonirk/gAradn/hSw+DDJpVS2sNJ\n" +
            "kgsUSpiCLL9181txtBrzXqHrjbG5gKgHqk11ms3pkF18p+bbhVJIqoKvOPXQRsGh\n" +
            "ijQBTvQGGbG/a5+janlcV3xosWYTsg95c0rzGjwRkm9EvUKgYOYjTgz6OKilZrn/\n" +
            "QdidPFDhtbpB6VDhGXC+YALSxTyaRtLy34lZJ4nH8To2iF23coh7pBlYcTphPZPQ\n" +
            "/eWjWibIoQ6tZfNRLQrW34KBx/EXYLMYS+9LwSLy9PKGZE7Zg1V5GXtDt9aKMVCq\n" +
            "BL7n2ZCT2sGlpa8r41ToWhguxuhJxxFXTDPBf5yPUN3nSH2aXF5peUIGU820EFPe\n" +
            "fDN377EMxJBrN8nhhM3ydTKW8qLbANsZUwH+PHWTYeMbY3aG4p4+9/LHoa2H/PDr\n" +
            "oZyM+gRKipTt68duTlRCJOve2YMfIeIoQ3Zy+ucj6/ao8FvprOBGYI9B1jGLfOF0\n" +
            "+sRVHcPJWql1109vU4XuRC6QuLMgYbiEGSdlvRpO048CS5/vVBzeUAY8hsBOPANf\n" +
            "dzGmUHNryHBc4PV4AswdCpak+reox2EgxlwxoW65W53lkdEBx44zHoHlp0MAzhgr\n" +
            "Qi0IzJXO2NNNX2mqOu9gmDgi+7oghMMn7RvraSGcpc3zKj8Sd6DILbS0mN7pmOnB\n" +
            "32rUgFl2PC9MLxeB+iM/DMQBtxjyzVJgi15aDAYEZDbyqqcTx6641Plz8GIfmWTP\n" +
            "xzaP/oluSX1vl1nRDSwFSWhFlLHtvnBSiklPMxBlbT9r+AbpXO77xQJPt626Uj34\n" +
            "gK4XqbE2e3Y4BFgzF4HFWM87GWzdsjNnsBJhJqncrGHCEgooN7Y+RckDoHUBBgyy\n" +
            "6iraHEMRISaaHYKx0QAeY+f1NLwhpTnE5PM2Kc9ZtLjpMm6YAJoHV/EpFJ/v3Vp4\n" +
            "MZotrYMdowvhGruAF+BgLdkgMaB78Uap1lCdGEiotissSJnzYuNFef+qqkEG3Be0\n" +
            "nbpvtMVmXVj7n4A64/kLs5S3w9NrQjLGbuQiKBaHyFlMsOxboIZSk+2Mj4yVg0zo\n" +
            "PAz5s/J9+aNbjfYx3Py4EDVH285sNrQff6ePaBBJcI2QqxFc30lZUfCDEC/cTSIy\n" +
            "qtAxUKl+Y+qexoEIY5r7dfOywVf/SQ8iYYRacvvPblG+7byOLi/Wa+GAfGxEyo2j\n" +
            "sHIqMdGC2VeqSCHptwRmUs3L9nZhJg1mK/SfpCPrvLMBdPDJk+u+WYp9HzHWMJua\n" +
            "gRu2jKi/eb2EkLmJF/DQHjvqcQROxhINRrK55+79q7bCIVcZQpEVJgmnPZuDUqws\n" +
            "s0v/CWytj0lsET+Kh3PAmExcWBxQWE2n7s8Q90Nu4q3lCRy/6pVn4NBxalO42iOt\n" +
            "/Ka9D3gU2Mmzlz1/NMrW4oGL5CRdPcswnnx+Mn6rn9cFti5SG8niBKFa4BkGsIfL\n" +
            "n8ujz+C0WQHdGSe0D2v/02N3S0QFYQ3BEMu+bsKM19F9R46RGbYWDp1uL83T8qRN\n" +
            "SE6oPCE9TYJbmhfJWqfGjkWyZ2A2nnoirmuD5L1svOtp/C0TLdNViK39puMeIAKE\n" +
            "15ab4TOlr3MdgI3u6HP4/sdjkJjnxDe8lUzya5S/xd1rXYSyrW3kw5Yh9EhoY5cE\n" +
            "KiapY+jBbx+wUSHxE7M/inJaRZEvJgxDf5R8GvdM6Dwc7JeyV5/KfqKhM9uzanMy\n" +
            "n0fHTWvth1BckC7cz84BzDuUSoVSw5duWkI5MTW8ULsGWvyEj9AkqUvIbOq2shdS\n" +
            "EyVHh6L/Gh0yRaev5xBeZ5a0wepOcauusbnW2+kLJoapAAAAAAAAAAAAAAAAAAAA\n" +
            "AAAAAAAAAAYNExQdIQ==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        // ML-DSA:87 Key
        // CN=intranet.adcslabor.de
        _request_mldsa87 =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIdnzCCC3YCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIK\n" +
            "MjALBglghkgBZQMEAxMDggohAKh5JYiMosaPRd9CYM5FDdmVC0imEKvnlREmhIcT\n" +
            "8Mpw4pDniws3Yh9cjA3UEvHbGyqiDzpQ6Zg+iZKguhBXC6g3fZvfPspxBIEOf/Cj\n" +
            "B0+NjYELfzt3MqMUev+BCKzPmcGikeKUT/9FDsK/ErRQc9wqhiufJIPr5TGlsnph\n" +
            "BptF07vb2zeYKw1dDq123ODDrIN9zISj1QMogmG2Xo0r83+V2YecAumHSXFkfyoy\n" +
            "Pg3hjYuc+QBOTM+NzoVwL40JeuzgNgaiuXD3VAgD0nupaFzAxhKAsGK2eM0Gf6om\n" +
            "hr3YuQJdPjO4XE+DXzLHw48x0mucr6oOMaCRPVzl+t7FbsmxnqEf5wcQ3MUcR7ZK\n" +
            "Tn2bf/wtjixJErymS/MIGbYIUFDq1LZI8KT3TVtz8K9KwakJdKXBWf45TzQ2D9Op\n" +
            "Bv3e21qKHoq2zxnpiF01Jq1KaaD7mcDJ2F5H4oH3OQaWlo55WCkaxKeoheq5sc7K\n" +
            "TvjZqqzl/XsSjPCpE9lNxdSbIfNfaMLt43yWLmDZf/PNeZuyPliuGLj4s77bkgt7\n" +
            "P0t8ZPicvv7Cc6ibkLW7gxmz2PN2JQX0pnMMLDhVqJLdqWUbMZup8aGa2sX+zDS2\n" +
            "icO44rDbkX19oZ50Gptw8LW6YG7AR8OSk1amTVrel1Dg+SjzNhjESnsdGkiCUujL\n" +
            "zNTLZwkoCDOy1WfOBsqxWfIvUigwJKiniuZQ39rPO+Yyro31nJ0zMBxjIT68Ks50\n" +
            "ZyjjLXX0ZHHqFXwEy1aarg64lAc2ojl0WE2uiDDx2b5u655RobLtVAdwW/dd9pxm\n" +
            "zPUZCy8dsvVLtbxTrpb5lofMc8KqRoAuDTqYsWhz+lUAl0RVvJhTQyZI6dbA4NH1\n" +
            "EyYfWDogqfOHOxw2NR3EqbkUm2MpI3WjQK9as3yyUhp1SrCq33bCn4979D4kWRbV\n" +
            "m41B8bUjPSWnpDaF8MinI9SpspguvdmIU7rnq9lcRBeL/E7nHU1stFqR16+yqnwE\n" +
            "g6J0Fg3lP2aVdTDnnT46dN2OLVLhnZHMOyrW+PNxM7sh2uPB75rfwPJhmxmRcF+e\n" +
            "rHw0UI7FBnmn0+esWFEIQA6yBpHrpnFf25qWTUZP1uxNhxVNQCCxO1A9cOokywqi\n" +
            "eYzWKayQ20wGS1O9m88+095MEYxMC7t3c8a6WrXm82JP3bqNZyL5JrPw3Sa60ldc\n" +
            "NbDs0GGvYl7eEFA80n3BW5CsIGyfWd/jw4AJeC8937s5x2obEfR6zYuzn1qUr4yX\n" +
            "p2zex7KrN7tu82DsDrqd+XZZyupwB9NPDh8lkmeth/Xw1bHdY1cbRJwBYhCqQGxu\n" +
            "GOSgGzg3qe3wXAVKGBrdMhtBAWHyvW2VXv7ibD/TlP3K1FtIy+DhE75LLl9n+o9R\n" +
            "SVzbVc8yDLhM5JDpVK3CykNPQAjdgGTWGdR0QaKdGgMTQ2/YJg1uQWqkAVCD8+iU\n" +
            "8hGWCPGqvHRSOZ1EpD4ycg6w6vUtByi7yAn1RxU9z0F2GqE1I2qtB5HGUiF4eJnF\n" +
            "FDJ1Ss71HCu0Yg7VO/8Iib/cR+jZZmHlIC7WsWxuT+0pFIpYWttqOoI7fZIFDnRy\n" +
            "3OEZHrdcqznUv5MJ3A81w3pLdmp3FyIJYfqPdph4ObvTJYzz1NZyzsyDrEa8JfRT\n" +
            "BhWFr2LEHLgT+//P6dPMlV7vVERhLG+8xerndIgax+hnq3iHy42ldpVl0cvxyZ0i\n" +
            "yxBHqjUnGp2FjZbFNPpSEfBpsTbxqf6TC7mk8jnzu2y/+1pkieKQWjJAXrw3lzn8\n" +
            "eZAaz6N4STLOTavZZ2cY6zVYHXL3D+4IvBZQMz7AjpPd9a2yKpRCdaBiB4rJVjUj\n" +
            "0a9sp2M4S7S+vZYi+sPKdEm1k00h/5VUhHcb/dXgY3KeY3UbXAvL9Kpno7fFqSIn\n" +
            "bsDWwFIPcg4ljV1kuD5eIUQo5N65AaB6uhvni/N0ADN50a3MMnESmyiyizu7QC59\n" +
            "uE4413Z590EHa21XgqiXDk5DmWDuSpRrp6IPqEHKSSavEfdCUxirWLYltR6JKEZ/\n" +
            "EImHKevUJG8XsdaTIhjjiGYkwdvYHZmW2V2fkob5LaXkSzilJ64AXb8ARJH+Bry6\n" +
            "umZsvUQg/LNMhWgKkmcXk1iZX1KNGD7XJwfNYPI5H8TmqKcDZSShieRlsGDo0gKG\n" +
            "fcId8sXZvYHsDRFERJlz/5RbkI+y4qVmSoe2lB1jAJS+xXIlfws3ZSO+0ctCbHU0\n" +
            "LDZrmEDAJ4taOFIWgPvpzExHkFYiadaepIVrSKhxm+s2M4WMq78IgZfiHw+TrZh7\n" +
            "4RpE/b6VgyO0lS3Kh7NygEqjRWcwyFUlitY+rHItKP53mOEQYOHdh0ZLJmmRDBdR\n" +
            "3aw/32DUxEfcX5wEfu+M+1kPe7OX6pkL74ZA83VzoMRNgywzoE9c0alPpys8/Vn2\n" +
            "wZllWeNhsIukKFdJlZtuAFQzpq23pUm1FQhWCZ5vE8UnG9m1Ko6lvTVO6rz9TvRW\n" +
            "Jj/hrlQKtsRb8Kh6wEWwIMpenWKHrs4v+jBYIGEH6CyAi/mSwciUXnXVa9e6Vl5X\n" +
            "I/tLv7NVeMGC3GLBie1jVSEZ5yksFdOv2mPGGyNBWKoXtWE9MRLIpE5T7UvLoROc\n" +
            "kwRRTUqffw5MGV0mSsNdpTF5M/RmqIjlIXBP+crGCpdzP4M2RKjMQqmkLaXrRoTs\n" +
            "kif8dg/tWnaKUzHbtjeejKO/y2nUrCdXX5oSjjg+nX0P/oEqk9wiONxM84fez7Tl\n" +
            "PBSHsG0sfkL4DWr0HBUN+NGAh5oXNHziiMcJuin1nQUtvq+SII02deqRClF88DOv\n" +
            "Wi1lBREZOXEaH8o+uaNfAhhf1etIC84BLuhTPV0+w9aBKNmerTJw1zkFc0btdVDA\n" +
            "oegjCXwUDPkKMZwV57EGk9Kcr95WBt3Psc+voAJo32XGMMd6jJH8WW8yRwIhC1qM\n" +
            "9AAjaEfXtejPTDgok1NHX6c/yB6Zk53vu5vucMZomCbbivckRZBWUkq3G9Gy7rJj\n" +
            "xUrIquqOXluYYxhW2tpZCJxQ8ktxqIbsxnsWARylosij/jaeVEewXNMBEoAtUOCA\n" +
            "vA8L0j8gCnmFvm5VzV59sTMKW2yNmCG2bXB9QU+ZTkf68IpxoRJ/wG+35Ka+ut6o\n" +
            "MRSg1VHN1Ir5IqCXtp60Tup5E6YwSVx/UYXIKiCfQSlN+Nly6f9cZe1fYhEU4Ii5\n" +
            "I0ZB6OXir3EvQ9TD5JupYtXzhz47jLmGi4gh/sk5hjFISGChAVossLrfbCbWiTT9\n" +
            "xFRdKvPTgmvRGF9Mx5oczLAInyNHcqoKdMjH4tlOgl6d+Ja0I3cuPutKSMI3Bt8Z\n" +
            "jEa4uN8LQWhWFuhXVSH8gcpAEfpksnjseMNB5hIL1U5MsBbl6QALMm9Kvecu24MV\n" +
            "W2fTYsmI5i95Lf5e5xWvW8A/kB46Tdiz4+Z6MxavgmlJlscBe/uKeH4OoYaealf+\n" +
            "vXoPOz9BV3+zz22aSuCF7kFZU6CCARcwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjI2\n" +
            "MTAwLjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYE\n" +
            "FMAAmG7mQgwC0C9W+IuucC4/h6b3ME8GCSsGAQQBgjcVFDFCMEACAQUMFlBDMDEu\n" +
            "aW50cmEucHFjbGFib3IuZGUME0lOVFJBXEFkbWluaXN0cmF0b3IMDnBvd2Vyc2hl\n" +
            "bGwuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQA\n" +
            "IABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIA\n" +
            "bwB2AGkAZABlAHIDAQAwCwYJYIZIAWUDBAMTA4ISFADnwH2CnDDDfd4nlh5PK5lK\n" +
            "B+uoOYyt9UIToUxJdnel32tHc7FtsEa9yhVtVvpjeJom/1XSYoMOChnbqlvNtpdc\n" +
            "Cxu697bSJ1WNQOzABtbzWttsNTMZh4LLEelOosXxuAKyRKKzz7wEqxRxB9q9Ak1Y\n" +
            "FjAVNi8VEQH1wY5732x751InvVpiQwkI5hRr6ypG7cqPQUVXikrBvdCS3DF+bjFU\n" +
            "FEngpvQmkX4M2drICiGR0tahyIaS5uKBr+sXr5NoM2M2eXaW2D0b6fTih15DNPyO\n" +
            "GjzARj4cvjtGrlHF09SZDMRzQoRA+fMH0nuEr/ckXBGxF4S8lPo9xeXLi2dWH2sc\n" +
            "0Xpz3vYLpkOCruVgjQE+3n+F1A7fyhuRHoFSqNF0e520WD1wV5o+8qw4WwhbOuCP\n" +
            "QGoEK9MQAFpj8CBdVpL3d5mMJwkM7dVd67BE+lDcbv+4xyh38sHvMibPNTN9Wmo/\n" +
            "vQ826boTAq5vhp53hAaA25DKCuQLAn5s7zmkWrNLN7DWCXzT1PWmcdr8o/5VGv6C\n" +
            "wpJlmAZ/fwpR18zQnV8Lg04fCJT5XyeBTog/TEL/ZYCAJfksEsSsJV/OPYn/Ia+X\n" +
            "EP/5/+GykB9VyXpy29JdpRO8lR0YemI5cwIEZ7sH8CXw2w9p4E1KMRCEeOKsPka/\n" +
            "9eF/9t/BNBGeFyqu3gIXsGNyUOTlLXuBdAMAJ63LBsihr++cBiX8Sbq4Goj9MbsJ\n" +
            "0jycMtp5UoiB/n8yRWnvxQCxWRIVxQAKtICINXJJ9rkePy15Yg/9Iji3ulGrjQuZ\n" +
            "cPOTOdGCmd1L71s6wshbyvkwjba7ls5jAIZ8gKjXh9DeAtZs17zdgW4/wREnD3RO\n" +
            "ajrv6s3Q3tEfxYA3i85J/4rV3Gtl94G2b+hWDi7Otcy8VsU81v5EV7OwLGii4gUc\n" +
            "LZMjJFcw31FpTe30AcSYm26VhBYx/H/bbVx90dDFDws+9f1HK0zn6vA3E6cs8HEd\n" +
            "tYzuyK22jtHV2bnVygwpX+gisOluhkgEpCCRahZ6878TWM4xOns//fWtJ4s/e69p\n" +
            "XYdNVk3+qx2K4dfy6uWLIGelsG5ZL49knZIggFwRYE9GhHtdNQXQBZ7HwKc5I3ZG\n" +
            "eeYzu5o9RNg4WMDdbl7qPbxeC/ti8nJItIlZILo63lyW+wZFtjPsbZVgX4dEMevK\n" +
            "QQgbDF68czF9W9f17w2ZQvmx8iBusgHFPnGhpD1alE0Fyi8pyeEDYUH/vKJxDdYe\n" +
            "+/wppR88MDGLDnMS0rw5t9nOujshD5E5XU/EaRaFvyUz/Qw7LFYh1AFookdiBLnn\n" +
            "mw66V+DnFazU36BRrkmo5wPKMP1IxNs87RlceAysZOB8o5HVW8aWvMVhWGJQjyvL\n" +
            "yabrnKwzZYyllsQIi3RSiI748DelMw+fkGg3FKvknKDtbTYZeLOtdAl2mtTMXU0i\n" +
            "j6VaKridW7f3ayBLMTHHb89FK8VKWBsgeaIU9Fu2AKKU+Z0944Cg1SCCNElqYKEo\n" +
            "zG8+gf8QhIqw8A29B55f867SGWxrneDWnjdTSd5Yn0nN/MzOBNB4wFbKVRldd9z1\n" +
            "Kye7oQvbFVi30co+Njm2vJ5j2GztuzE3wcZd7+tXlG9MRaWc5uMqG+GvYg7hZUlc\n" +
            "Tpjs7U7fRLy6L9ppC3cx512VNScEGm8iP+G+pX4u3Q9QMqOuAALIAXT9lf93VH0L\n" +
            "BNp3+i6dZHMa/oqdi6xiwBqszCEMCQLcNa1DgLY0MuXHHYE7qCgbfu+WctuLc347\n" +
            "WyDhaWIMMNSkQ1ql8K52dmsrx2B8hQC7IBgXajiT2j3QknMxmsurqfCZxQa0KOW/\n" +
            "OQAkVu12uyXWjTuVrZ9xyhkgVJEFyIOLAL0X9IKm6iikw+uzeuU7XZSGxvfDygrP\n" +
            "uzcOB8gFw9USYsclTopnrKO16kK9qnSY37US3evQ3K/RGtiN3Lgy56pQMC7s6FFX\n" +
            "HeBU2wn+Vvm6laYs2LwQ/iPpGCsitZjcvDMk1MH4SLX/BLGgpqY+5zi0TTLrr7Vz\n" +
            "iSLk7T3kCZjn6jIdqaPGV8xmklBFZYEeQWHbfImTlDeW6g/IEBLSWelLQGw+02iX\n" +
            "tiSpCjFjF2F/qIasE6kaZMSeFOg4HMkY5do4hZhMpDSXlGnWp4U0Ib7M9KAm3LuG\n" +
            "xT9sKGNSXUVrTzjIPtlP3m8GHzNADCDnS5ohaW+zg7kPbQ/CfkhdLJMDeAp+30bI\n" +
            "I2VSmbacDp+W6jIa72AKqbNHhB9iScqIFBh8OuCt/bvL1GWUPRsrbMwBMkyH5FQi\n" +
            "siuHZvsYf6iZckjOxWlrOEXahAIWiOPLd1M+mip2l+zuXKWqp48qwCOOls51NBrK\n" +
            "itA3/TacOO/UpKWeqIOrVMfwUcRrkKf24jr+Krv6tea7/wgDNZBKQvXByfNmsXA9\n" +
            "Wtohl0muKR++P/+I2OcsC5IDBcQYc8gsIN9/sAAGQv/QCuWMmwiZ/XVdCsoirCab\n" +
            "zc+T8juy4rovK6gJMDlsQgaGi9yBRrhuoMN86X1bIdfESrfpDvghBO8khszkV3Ai\n" +
            "NkldL02vuBEYZT+LiNZSe7K9C0/Qg5wnLonkLhP1BJmjdB0SJal3JgAAwnS33/kj\n" +
            "suCBv4pgf1iqIBV7tsEiqWogKQs3ImFyf1zB+ssgf3v9PkmuXJABR41T8TfIrexW\n" +
            "qox+tmeclLdyvpIMXI4I7xe29KA4820wlXPcZ9yBMP38BgUNUMbMs8Pi8+maCg6m\n" +
            "T7yHjqFdImOlqNUFXpZq5yuzieDyFRdYW37FG5qIFy0/RG9pxLibXeDPI3AL88Cr\n" +
            "mLDaq9JduagXO/61ce83FK6r1O2ZcyKqn5VmMhD9D2W8Lkx0X24y5sc6gU56ztoy\n" +
            "gB/QypVaWPu7GaeOPaQX1vkG2gdOSsKxNLZ2mOZ0NJpW3jjW+m8TT09ezA0tsYLx\n" +
            "B5hZPAULK8kl9vr1C+HOSad58AQZQqGcf1gbz3z3khA2FXK4P6PCX/DBuaLos5Ov\n" +
            "s4Ix/cq9FqP3hwzrD375KEZdV2kZ3/oRCQG5J6+CHDB+TJLEHRrabJElaKTPUooK\n" +
            "fAafGDkeXY1NWalzy6a+4lUQJrYHWkFWQ2l38+0IxFWmvupjWrKyonH/pRJo4iwf\n" +
            "LRySzOlBrcQsDePI/NeSsAlvYy3G8CIPXmWxxd0fSk7tNx2YdKirWxTQ8Jmog84t\n" +
            "g/LlUlYUiF9XW2wAn8P+vt5Jo3TkWKLgLTEQOTUH0v5XRUVEEHotIBrJkr82L+2t\n" +
            "SAijkpQ8BtTVaPFqylroOZU8XHuDldZ+x7pPSKGldZtFDsTN3s/ZZQVKM+7FejT1\n" +
            "iMf7M7ypC9ilutZzxuUUF4GDhw8C+eIRuENvGnp6oMgDYF0xB4ZPKyLygoJN6VS1\n" +
            "kGxv97MjaCaIh8IYWoqZy1kpwZFLNk3QUXRwmdCUCHWfx1OLb0jCHR+oL5spduHA\n" +
            "dABaP9Le47g8ZhEm6XSQNfRr18Vlie0B6i8n7edCzVoOCQV1zOc2ccs48tRWhUo1\n" +
            "a2gGdhNVFUC8f4KxVvD1xI31C7uqklVfUmGK9jdgIOMxq1rs/4rcYuBOiZjl0xND\n" +
            "AI5h2OjaOz5vA8mP6GKe3bLV5pPR8VRp0Wshho/yr8XUTCbUq4GNg3S53YVSADv+\n" +
            "30JiD/c4mUZS1PyXO3GJ3LLaiA8TRS96CWSl4e6UK/GuLK1LwGC+oaqD43BMfZZn\n" +
            "DN46IRqljnjRix+nQovm7Tx4hkx4HPWiIC96ZG6bUxOBgh8qeiEgr1Fxw94dMKFw\n" +
            "lg6Hs3MnXcIg5ASkVqb0fBaudtCbxpTONNgbwqJHVnDnAg9+4aoJdzswJibA0Wf/\n" +
            "BWjD7lBqQXNBS5Ec/VYUqahfccBbDfSQwYtbAGvUHQTx9DKubAc20O6pGjAm06zH\n" +
            "RiRqmMLkbCXmZwXHsVIFZfP5l324jPq3aPCKS23ci7pXVFfG1FjitOUqzuqyGeqP\n" +
            "+rVk8nEOtPtbjI8+A7ph0IPa34TCWrfuHsIgJ9oYfd4/ezXpSDYIz7Zyl4l5ZzRN\n" +
            "ThSB7Bg7/8ktxOQ2+s9lRyeCtn2oY5lssnsf+3Ld4bVT2AcCiJs+ZQuB74pzQ1XA\n" +
            "9d+EMm9xpCfjq76td10+f0PwOhYRJcl/S50+TDGmomFgebwflEo7bUaRLZKTog46\n" +
            "5n3Myp4WaM6bJAwFSx+HwvOPiJl0RR+kHMxuyYhJQWdT/4uaZh7VAQ01racmkl6T\n" +
            "OPiuQhUW0ufeJmjIYPfgJ1HHkzNDDlCXRCX3y/lkVxZAKjxlcHJtbcwrQ8MbpwYf\n" +
            "IyBhbw15JlW8GozJgxyYZCiMR+QjOYTbIKHIw1uu7DezOTVbc+SUfcdPVKoLQdtq\n" +
            "zW9gZd+9i/KkMqS/30SNcR4DptYstyba5I4y4ISbihubAoWohgaab1vdniOj6dqC\n" +
            "RL47wtcHn3eBoJ0Mo1A6EChCMq7OhITz8/eFQR5/QvPSjzSFW7kgGiJW69viS2Vf\n" +
            "S4mEa1o+3Axq2brIknjXRAMlr2DPWhFAY7JBrmPg40qSIUiLg1jrdE4gZ7sq+to5\n" +
            "FBQOH3n/HKJCPH21ryShdy5NFdaf/o/ZhJRdOGJ9uHgLKD1PJIemX/w43igxhWpA\n" +
            "7MdwkNgNHLjqKiN6wbmzLngZ6umpCx+r9EN7O1tkfBU2CiytMk4vImxEvLKfhLPp\n" +
            "ltFpbcAWmb2UXSgcuGO2OsZAWKTad7UnoH1SrAzDij5KgLmjZXIk5x5zQCjKkUDZ\n" +
            "oE9tJdph02wlzwlm2a2lH/VwYItB0laWDGo6Gd0tug1/bwmZL+llu/ZlOLrn6B6z\n" +
            "mkjPCRPD5kKz8NQ/z8HIWEkqr+5v2jann/1DA27QttuFvRAXB1oa5U8Uai9qzptU\n" +
            "dsBnTyBG3/2mSa5AI/0Hyyy1A7iGdfzA74/chNHLAQHn8h68o2ZR2ogGV6TYD9A0\n" +
            "WN1ucwyZJiRAzT/E0TBXRnl8ON4iDXznCQtNkNXeUolkX5+eUf5l+3P3d4Acoybu\n" +
            "+9RbSQgEYshviKnT4S6SWfLJIMvyamfdZxNtifAdXoaJr668Ub5MwJzaQUrNkeHF\n" +
            "TbWsLnuFxeLZh4XDsFBtXnkiDzxz3r2D0Ub5bpT1PQItk/f0gugDymvDXIj4wR12\n" +
            "W8xt6w19wd338epgzdSCwVjuipeUFEVIYKTnwAXQe8i0ORV7UkaCtINiVc0LYhR1\n" +
            "f1CAsABdVY+NsferP6FnWXiDCfbGVPD9xD3VseAt6+QIhVz4I4gzaaELyK2KktZu\n" +
            "jR8b/3cF+T8U/+kQ9vwyVKNaa7RqLofJECcHGKZNPVgk/jfbm7tjfEZKpqnA5V12\n" +
            "rd+qiTPcvKWnpwbHoFRmDMii7LgzHWmIulF9MDn1PPkgZy7qXMCwFFvsUWm2djGW\n" +
            "2Oq6/CUCGLxUTlO8SF4WP0Vwr6BmzlWk8du9ig6weHfOw+ZXiD3ZeCjJPWQD6kX4\n" +
            "nqPpA+8ogOb/2A7MeMqDc0cKRCpzTn2ST5cT4oxw8Sox1NbeP+gDlcb5UCaWWRmD\n" +
            "3ahqgguOfy6r7f/QPUyFcyHVqNhyD1pfl3eJgt48k3wdl0rPcp+mRc2mw5whEyIi\n" +
            "3LhpSRLnc/P50GaRrmx9YOYxcJRUaWnFmyq/QbtAeY4zArVFBrJU9uq5gQEt0jsi\n" +
            "JfSm+O2Y4vdmWhppEApCJWNsXMPRHvWjmCmXyR0IZ4Tj5tk0JoNKbTfYwHoPuCV7\n" +
            "t7235g8yAo0tzZTydqSHwRMe4BlD2ngo5wreh0AFBBlTUUpVSDQLwcIQevtmJtTA\n" +
            "26y4GP3z0mV+sd021UAdwYozMOJtwj1bFgW8zNLlUjSLHfwLOLLDf4Wy7t2wGnyH\n" +
            "oDxVfAFm4z0+8DA3o28Wtw7hD+ZzpY4NYcT/tCq+UU1E8Wi5tiBqRX7jeImZ6MAw\n" +
            "gix6SxPaULrXfxTbrbrUJr0yclQxWLpCKmUIPfJVQAzfFJyU5xKGm36HaP2alCk0\n" +
            "VY8bIkKehjSWHsZWTeBc39H5GoA6ZE2EZAv6zJIEoJ8ntl3eCJ3TE47ndlbgkuCB\n" +
            "lJ1zIqSw3kMbJKo/S+xf3wl9CPSZUnQQF2V2BDzG3eajhx8mRCRKFJxMIt1Q5WUZ\n" +
            "L6PK39i4HyhRgZeTrQI78iElNTk6Y4GNpdPiSXafrb7Bze5oscPTGTNWl53DCTk9\n" +
            "SElOWr7/a4Y+YGFpmKQGFS81OFrHyNHYAAAAAAAAAAAAAAAAAAAAAAAAAAsTFx0m\n" +
            "KC44\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        _template = new CertificateTemplate
        (
            "TestTemplate",
            true,
            KeyAlgorithmType.RSA
        );

        _policy = new CertificateRequestPolicy
        {
            MinimumKeyLength = 2048,
            MaximumKeyLength = 4096,
            Subject = new List<SubjectRule>
            {
                new()
                {
                    Field = RdnTypes.CommonName,
                    Mandatory = true,
                    MaxLength = 64,
                    Patterns = new List<Pattern>
                    {
                        new() { Expression = @"^[-_a-zA-Z0-9]*\.adcslabor\.de$" },
                        new() { Expression = @"^.*(porn|gambling).*$", Action = PolicyAction.DENY }
                    }
                },
                new()
                {
                    Field = RdnTypes.Country,
                    MaxLength = 2,
                    Patterns = new List<Pattern>
                    {
                        new()
                        {
                            Expression = @"^(DE)$"
                        }
                    }
                }
            },
            SubjectAlternativeName = new List<SubjectRule>
            {
                new()
                {
                    Field = SanTypes.DnsName,
                    MaxOccurrences = 10,
                    MaxLength = 64,
                    Patterns = new List<Pattern>
                    {
                        new() { Expression = @"^[-_a-zA-Z0-9]*\.adcslabor\.de$" }
                    }
                },
                new()
                {
                    Field = SanTypes.IpAddress,
                    MaxOccurrences = 10,
                    MaxLength = 64,
                    Patterns = new List<Pattern>
                    {
                        new() { Expression = @"192.168.0.0/16", TreatAs = PatternType.CIDR },
                        new()
                        {
                            Expression = @"192.168.123.0/24", TreatAs = PatternType.CIDR, Action = PolicyAction.DENY
                        }
                    }
                }
            }
        };
    }

    internal void PrintResult(CertificateRequestValidationResult result)
    {
        _output.WriteLine("0x{0:X} ({0}) {1}.", result.StatusCode,
            new Win32Exception(result.StatusCode).Message);
        _output.WriteLine(string.Join("\n", result.Description));
    }

    [Fact]
    public void Does_return_if_already_denied()
    {
        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result.SetFailureStatus();
        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.NTE_FAIL));
    }

    [Fact]
    public void Allow_commonName_valid()
    {
        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Allow_commonName_valid_inline()
    {
        var policy = _policy;
        policy.ReadSubjectFromRequest = true;

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Allow_commonName_valid_countryName_valid()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de,C=DE
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDejCCAmICAQAwLTELMAkGA1UEBhMCREUxHjAcBgNVBAMTFWludHJhbmV0LmFk\n" +
            "Y3NsYWJvci5kZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANYahn0j\n" +
            "JPGIDShHX+SzFMI9XnAN9iky4siQQV7TcpkJ78+S+ZJ+5o8io6AwTXiZt60ox9Yj\n" +
            "wp29PawCCVKeDKuY8sjoiOPqo3pUg0WeXCrD3zKKimb0TF4RSwCg+Ymf19MdeywF\n" +
            "jO+7oWzDheQV+UuIm+cT4ipqgIfkML6iphyy1SWxXl1jYCl5yrnSrG/9iz2eZdpl\n" +
            "WtDQX6FVaixWbJhdy9Wtk/b0mj5I27yapwjiG+cvVuaQ9S2iVR4N0rqVirNPLQgf\n" +
            "+V7UJbUIQCmklqU3oeAWXY7k9ryW8FTeQPEAZD9611C7A0EANm2EUVP+iJ08iUIy\n" +
            "S1AUSVLqopBjEf0CAwEAAaCCAQYwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE5MDQ0\n" +
            "LjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFCyR\n" +
            "TDtg3TJPfsJBNynovfc2dt+8MD4GCSsGAQQBgjcVFDExMC8CAQUMCm90dGktb3R0\n" +
            "ZWwMDk9UVEktT1RURUxcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3DQIC\n" +
            "MVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAA\n" +
            "SwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0GCSqG\n" +
            "SIb3DQEBCwUAA4IBAQCekmxgcJmTixtnAnWpj4ClO9WS5zJQIBmW9lC9E4zDHY7t\n" +
            "ZEaBkmdbf3lPmeMt9+/t46G97qt+zGpodJIXCquTPnAzVRNzJsTLC9G7pK557Jd0\n" +
            "55wOmhQ7nAhaR8wGHAhowSkiJDwthEEP4JUVhPmmG8fxBam4+NveaLVtmmM2HK/M\n" +
            "D6F1YJ0Jateh0gU/DSnD95xrXngfTzrKBhtD7VQrBXsbfpeysjjFfwqWNPR9cBNV\n" +
            "U1QKopiXRbWStlv0KFAJ7gHVNEkmAA00mbaEufmHbAOr2z/8RcrTRgK6Q14Ib/YP\n" +
            "P7MNEhROVnD5RdVp793twbYgnyLW4+UIbaKYX+t5\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Deny_Subject_present_but_no_rule_defined()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de,C=DE
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDejCCAmICAQAwLTELMAkGA1UEBhMCREUxHjAcBgNVBAMTFWludHJhbmV0LmFk\n" +
            "Y3NsYWJvci5kZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANYahn0j\n" +
            "JPGIDShHX+SzFMI9XnAN9iky4siQQV7TcpkJ78+S+ZJ+5o8io6AwTXiZt60ox9Yj\n" +
            "wp29PawCCVKeDKuY8sjoiOPqo3pUg0WeXCrD3zKKimb0TF4RSwCg+Ymf19MdeywF\n" +
            "jO+7oWzDheQV+UuIm+cT4ipqgIfkML6iphyy1SWxXl1jYCl5yrnSrG/9iz2eZdpl\n" +
            "WtDQX6FVaixWbJhdy9Wtk/b0mj5I27yapwjiG+cvVuaQ9S2iVR4N0rqVirNPLQgf\n" +
            "+V7UJbUIQCmklqU3oeAWXY7k9ryW8FTeQPEAZD9611C7A0EANm2EUVP+iJ08iUIy\n" +
            "S1AUSVLqopBjEf0CAwEAAaCCAQYwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE5MDQ0\n" +
            "LjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFCyR\n" +
            "TDtg3TJPfsJBNynovfc2dt+8MD4GCSsGAQQBgjcVFDExMC8CAQUMCm90dGktb3R0\n" +
            "ZWwMDk9UVEktT1RURUxcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3DQIC\n" +
            "MVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAA\n" +
            "SwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0GCSqG\n" +
            "SIb3DQEBCwUAA4IBAQCekmxgcJmTixtnAnWpj4ClO9WS5zJQIBmW9lC9E4zDHY7t\n" +
            "ZEaBkmdbf3lPmeMt9+/t46G97qt+zGpodJIXCquTPnAzVRNzJsTLC9G7pK557Jd0\n" +
            "55wOmhQ7nAhaR8wGHAhowSkiJDwthEEP4JUVhPmmG8fxBam4+NveaLVtmmM2HK/M\n" +
            "D6F1YJ0Jateh0gU/DSnD95xrXngfTzrKBhtD7VQrBXsbfpeysjjFfwqWNPR9cBNV\n" +
            "U1QKopiXRbWStlv0KFAJ7gHVNEkmAA00mbaEufmHbAOr2z/8RcrTRgK6Q14Ib/YP\n" +
            "P7MNEhROVnD5RdVp793twbYgnyLW4+UIbaKYX+t5\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = _policy;

        _policy.Subject.Clear();

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_commonName_blacklisted()
    {
        // 2048 Bit RSA Key
        // CN=intpornranet.adcslabor.de,C=DE
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDcTCCAlkCAQAwJDEiMCAGA1UEAxMZaW5wb3JudHJhbmV0LmFkY3NsYWJvci5k\n" +
            "ZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBALeZtnbJ7tYhH6O5BNRd\n" +
            "INSBOL2osdzE1URGixiLfIZAvSmLYFhmKhdqY1S7M8EVM8IWzISSK/5BV/cm5fs8\n" +
            "TchY6x6FLQ0RsVT7xEGkc1sMcBxU0r2ZSm/stI+39jsAqWPeUNcfCy1BCMClo3DQ\n" +
            "JPycbYMhH8KdbCGF8FHb/VGgQFK0+svyu5ARv97YKFaCO7deQuxUIq2PNR+nOVRP\n" +
            "4xph6uJiAoLCc+lKnxlPk3TuSCePhmFuWoXcxm0lAgMPuIvsABDZQa1ixuZMg0RI\n" +
            "0FPv25SDPckSM3Jg7AG5i6uVJn92KHYsZpdmdgTpNNnAIB0mDL4clUJKA/w+IJR4\n" +
            "LS0CAwEAAaCCAQYwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjIyNjIxLjIwPgYJKoZI\n" +
            "hvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFEE3TH8pts/+ja63\n" +
            "atreGLAs7TLeMD4GCSsGAQQBgjcVFDExMC8CAQUMCkxBUFRPUC1VV0UMDkxBUFRP\n" +
            "UC1VV0VcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5O\n" +
            "AE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABT\n" +
            "AHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUA\n" +
            "A4IBAQCyLyxLWANLXjwqH3wYXLedYkJxnK32FNVRYgB3Bl6n/W/dDNFidqHsTvEI\n" +
            "kVvTVVUUq/g1GACCkPcyBWnFqXp0Yogeq1j304yuk5jTFAZVg33jaIuWfNXkbH3i\n" +
            "mXHMbDSWYIxowwSbJBJ3QdNEgI8R/jpyIG0nkya7g9wJpUJunnv/HBLD3ejcunZ/\n" +
            "aRlcrkzuj6u6IgrasLMTDAOYz74PugBZXjKrtzlK12Tv5sTpPltg8o+Hc9AwBiUK\n" +
            "JjNtYt4oP6i83vZoXIa9HVXUDNfc0A93egPcQlP1YjCuV3W1nIiv42EpFUwzEzkX\n" +
            "DWVo8W9v/Qk/pRTk044/v3vlqMcD\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_key_is_ECC_but_must_be_RSA()
    {
        // NISTP256 Key
        // CN=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIB5DCCAYoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMFkw\n" +
            "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuMAntMo/tF+VJie+0Ou/VWJw97zFvZ3D\n" +
            "013S3Dbh0mTQb6km47IHX3DD5KBW6Ks8iAec3qvr+jYnYjHKZFEuZ6CCAQYwHAYK\n" +
            "KwYBBAGCNw0CAzEOFgwxMC4wLjE5MDQ0LjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNV\n" +
            "HQ8BAf8EBAMCB4AwHQYDVR0OBBYEFChDMOcwzSJNbIlwS6/SYZFvkv27MD4GCSsG\n" +
            "AQQBgjcVFDExMC8CAQUMCm90dGktb3R0ZWwMDk9UVEktT1RURUxcdXdlDA5wb3dl\n" +
            "cnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
            "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
            "UAByAG8AdgBpAGQAZQByAwEAMAoGCCqGSM49BAMCA0gAMEUCIQDvknuOQ52q4iMv\n" +
            "yEhQ5WYYq+7OvfmyVdDZcSoO/b1IkwIgTS/9EQNud7IuxW/639FxV+oS4PIssYn5\n" +
            "zEjZoYSctNw=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
        Assert.Contains("ECC", string.Join(";", result.Description));
    }

    [Fact]
    public void Deny_key_is_DSA_but_must_be_RSA()
    {
        // DSA Key
        // CN=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDKTCCAucCAQAwIDEeMBwGA1UEAwwVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "tzCCASwGByqGSM44BAEwggEfAoGBAO0pW3N11jj1ovOSjsKC12BxxrxoV+ZyCMFS\n" +
            "9VtXC8ZeLnEzYvmQqtEMnwTcbddA0UMK6/tx6Q65mT3tA3CB2w8Dnuz1K1+Xsq+c\n" +
            "g684Txs9x2hKHvg3+dd7X4i96b0OGztIFa+saK35Aqus0OIK6DxyY8msADOPvQvO\n" +
            "ESdLQz51AhUArDwmp8oJWHMRQGYSSXT+heZv4UsCgYEAvZSPRoBjMJAJQ1PIw2oD\n" +
            "A9PCRDWPeHhXmtwH7Bw1LcjW/9m9jxxWkxNyjVcCh5eWek1X3gWYjT9petwDpyiX\n" +
            "wGW7vSoGge3POct6uuc+fZ9W9I00ShaXKrMswRP5aiWWYTcFjoCNZmQkH3tOpV1L\n" +
            "S9prHA0aUWYms6S2xpVKY3sDgYQAAoGAajFs3WdQ0iZ8c6HeQrcAmS1ri7wzyIML\n" +
            "xqRGLONE6cMGeSIha0RMblLUBlz+QhPa9s7/Z8CZmwpLvP2WvbM8I6Ylr4lQnWFl\n" +
            "giHjgC6OV3V8XQIEQC4qv2y/V6mEYy/wfN7EZHfzTFHOM/K9dNLcZG+M9p4hlAaF\n" +
            "D1MrpcL8s8SgggEDMBwGCisGAQQBgjcNAgMxDhYMMTAuMC4yMjYyMS4yMDcGCSsG\n" +
            "AQQBgjcVFDEqMCgCAQkMCk9UVEktT1RURUwMDk9UVEktT1RURUxcdXdlDAdjZXJ0\n" +
            "cmVxMD4GCSqGSIb3DQEJDjExMC8wHQYDVR0OBBYEFHWOFhAX7nBcYtqM6DMJtwMY\n" +
            "wRlPMA4GA1UdDwEB/wQEAwIHgDBqBgorBgEEAYI3DQICMVwwWgIBAh5SAE0AaQBj\n" +
            "AHIAbwBzAG8AZgB0ACAAQgBhAHMAZQAgAEQAUwBTACAAQwByAHkAcAB0AG8AZwBy\n" +
            "AGEAcABoAGkAYwAgAFAAcgBvAHYAaQBkAGUAcgMBADAJBgcqhkjOOAQDAzEAMC4C\n" +
            "FQClIMEQB63vbXFRbnR1iFaiZ6yJSgIVAIUo93U3SJG9+KmkinmXSSnmX6qk\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
        Assert.Contains("DSA", string.Join(";", result.Description));
    }

    [Fact]
    public void Deny_key_is_ML_DSA_44_but_must_be_RSA()
    {
        var policy = _policy;
        policy.MaximumKeyLength = 0; // any

        var dbRow = new CertificateDatabaseRow(_request_mldsa44, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
        Assert.Contains("MLDSA", string.Join(";", result.Description));
    }

    [Fact]
    public void Deny_key_is_ML_DSA_65_but_must_be_RSA()
    {
        var policy = _policy;
        policy.MaximumKeyLength = 0; // any

        var dbRow = new CertificateDatabaseRow(_request_mldsa65, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
        Assert.Contains("MLDSA", string.Join(";", result.Description));
    }

    [Fact]
    public void Deny_key_is_ML_DSA_87_but_must_be_RSA()
    {
        var policy = _policy;
        policy.MaximumKeyLength = 0; // any

        var dbRow = new CertificateDatabaseRow(_request_mldsa87, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
        Assert.Contains("MLDSA", string.Join(";", result.Description));
    }

    [Fact]
    public void Deny_key_is_RSA_but_must_be_ECC()
    {
        var template = new CertificateTemplate
        (
            "TestTemplate",
            true,
            KeyAlgorithmType.ECDSA_P256
        );

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
    }

    [Fact]
    public void Deny_key_too_small()
    {
        // 1024 Bit Key
        // CN=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIICdDCCAd0CAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIGf\n" +
            "MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4gudRrmHIWnEofR6eoXBVXsyuzEgl\n" +
            "3ZNW2I3pKmp3TDIYhdS0pXbyJarwk7KkCs/r9nwc3lwmT3N3Xb1Aav6pbLbDsnwz\n" +
            "nhEtG7RKaz+nqfl9DZ2mKZpq/GohY7GCDaPX4ExXghdOGt1UDvZYAdp/JQ3q0RZw\n" +
            "saOym41igzzLyQIDAQABoIIBEjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTgzNjMu\n" +
            "MjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU77iM\n" +
            "Ld0M+XI10iyyIjiSep/AoLMwSgYJKwYBBAGCNxUUMT0wOwIBBQwaQ0xJRU5UMi5p\n" +
            "bnRyYS5hZGNzbGFib3IuZGUMCklOVFJBXHJ1ZGkMDnBvd2Vyc2hlbGwuZXhlMGYG\n" +
            "CisGAQQBgjcNAgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0\n" +
            "AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABl\n" +
            "AHIDAQAwDQYJKoZIhvcNAQELBQADgYEAZNh5xaK9rY1/u2UstSP6p4cz7YU/c28l\n" +
            "J2x0QJYmIwHg7yaSpYMY2UhVbb7Mp6+0O+IVSajHOYenUE3BEOaCcIZphbp4kzIy\n" +
            "TEnrYEPMbeHF2b1oK65mxdBOL4pdSEg6kHzmP7WvT5XHEmjDdcGSa413lwDIcYCr\n" +
            "JMXiY0xmEBg=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
    }

    [Fact]
    public void Allow_key_too_small_no_minimum()
    {
        // 1024 Bit Key
        // CN=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIICdDCCAd0CAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIGf\n" +
            "MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4gudRrmHIWnEofR6eoXBVXsyuzEgl\n" +
            "3ZNW2I3pKmp3TDIYhdS0pXbyJarwk7KkCs/r9nwc3lwmT3N3Xb1Aav6pbLbDsnwz\n" +
            "nhEtG7RKaz+nqfl9DZ2mKZpq/GohY7GCDaPX4ExXghdOGt1UDvZYAdp/JQ3q0RZw\n" +
            "saOym41igzzLyQIDAQABoIIBEjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTgzNjMu\n" +
            "MjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU77iM\n" +
            "Ld0M+XI10iyyIjiSep/AoLMwSgYJKwYBBAGCNxUUMT0wOwIBBQwaQ0xJRU5UMi5p\n" +
            "bnRyYS5hZGNzbGFib3IuZGUMCklOVFJBXHJ1ZGkMDnBvd2Vyc2hlbGwuZXhlMGYG\n" +
            "CisGAQQBgjcNAgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0\n" +
            "AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABl\n" +
            "AHIDAQAwDQYJKoZIhvcNAQELBQADgYEAZNh5xaK9rY1/u2UstSP6p4cz7YU/c28l\n" +
            "J2x0QJYmIwHg7yaSpYMY2UhVbb7Mp6+0O+IVSajHOYenUE3BEOaCcIZphbp4kzIy\n" +
            "TEnrYEPMbeHF2b1oK65mxdBOL4pdSEg6kHzmP7WvT5XHEmjDdcGSa413lwDIcYCr\n" +
            "JMXiY0xmEBg=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.MinimumKeyLength = 0;

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Deny_key_too_large()
    {
        // 8192 Bit Key
        // CN=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIJeTCCBWECAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIE\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAwZPi+tCoTBT2TQ2lu2FTVuZ5\n" +
            "Mli5r1fwPH2Pvymja0RGtspOu5vCWAMi5esyTJka/PfU/kgBOuDMzMRWepyHwMlN\n" +
            "shVWEDNKzYT7GcnELzgKFKBfbiiVvPshXEzr13cT+lKyioihrL5g1ksOV+NqSm4+\n" +
            "Iq6KOPRTxcqvJT5G96mVZ3TsfcQKB2OlATzo8DHXVqPS9dM6hnnMbOK2l7ohg1Q4\n" +
            "XC5zzmR1diajzrsFECGTjJRljxm2gtlth3aZXSE4Ep9FQxcc0/BBWMaltMHyeqaF\n" +
            "3a/g4+KjCtRrMeK+NIiJFHxIVlroclY8s59lu+ekqsSoq/vU8nLpRQV5R0D8ER0a\n" +
            "Lmx/tlRT4PiX1W6dbe0rqQGcF6vi8vmaKhcrc60suUex/5CP0i+bDfhkmU0x/s+y\n" +
            "khcr0+yl/FnUOAPLMSerYQZfQVYaZeTK7/bWi+5jySVjagZM752mf8KKWDFqavZU\n" +
            "tDlEu3wZA+kI7ziZsurT8dy8IhRE5QGSLYFExXj2W+D9N4IZZObPGeALc2N50Q1F\n" +
            "dznOwdXVyTlAhGbGvF67/FAdPs0HXBRSiRxogSwcDDdVw9wp0aXySaA7rx55agqR\n" +
            "04WBoSg6ELW3se4M+/EAU2dnC6BB6QLV7gcwGk8+9S4GHL8TguaecYrQwreqMBi9\n" +
            "JhVSa2HgsNBOxLySkAm9UCihlVyk6suPrOF6yE+PRuyPAd2bTbQrBUhm8JNGLWFC\n" +
            "NXvLHN+LOzxBxe3v5npkq/L/CUIPxBuuAuq1OjMsfzfWo5iCZx7R/0SCJbu9c2Ay\n" +
            "MxA3/NeFUF1kNkj7+Y8qUCq8EUvZp8INJBiVCfD/G5kQO4SD0/XZWVqGXs8La0A1\n" +
            "Yk53+Ez7PDLGmC35cA6oO3rFNZAsVZT+EON5t3JWrIt0+RhwQhdNbXtsd2pnewmz\n" +
            "CneCh+hn1iglqO/QpDEg6hXYx8lkwy8vjqrO4rjrwbMJYwZDmRam/eweap5/boBr\n" +
            "nttYrYagjhw/BHBd5aFb1Mk+0rbRd2w08LObC1gdjJxgOi+fc3Z1r8Hn+Bd7GeID\n" +
            "V5Sp3H+2qUdeHiuui/7fwCA/pIT2siWefBH7HZ3eMip9wx7Mm4q3mv4Ie9jyEShg\n" +
            "D+lx1IlTgf37Byq2NhsC9Ph7kdLFW1iAojyZ5UTLugGm7JKruybXcRITBFDTXQsB\n" +
            "0cQ3i+JsBxC9xX4/u9Ph/wH9QiX0h5hwzSY5S2IfjYeeXfiCEG7lKgR0UpqKPWrZ\n" +
            "77eTWXwoSdjzfBqDu3TjXsdwRDbrxOk/iVeC+tN4h/cjJdBB4OOAdHFRFHKobqoU\n" +
            "KFGJD6NpdUklRu9K1M95M4wh+Qe7QJjYKvTCuMzW34v11A7htDsDMtk9lDggQQID\n" +
            "AQABoIIBEjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTgzNjMuMjA+BgkqhkiG9w0B\n" +
            "CQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU7qxAt+UX4mKIM29ua/1t\n" +
            "zw5Y1kowSgYJKwYBBAGCNxUUMT0wOwIBBQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFi\n" +
            "b3IuZGUMCklOVFJBXHJ1ZGkMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcNAgIx\n" +
            "WDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABL\n" +
            "AGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJKoZI\n" +
            "hvcNAQELBQADggQBABqsWv1ziFWM2QHMU5Rz/WqTT6Aw26RyQpzBXoJWaMnzbdKz\n" +
            "4RdXbe+9wNkJ3JGOlOSWpCLkX4P7/GlH1Y0PGpdstyOWIvAra/DM2Aea+aQj0tN7\n" +
            "m7Kah0VtyPwHyFi8V5P9BCJnm0LpeIwdI6ar1tKeLfhSWFnKR+jiCKg+Os8K8ZjK\n" +
            "Y9170FdR8VgYqqnRTHNl1sep9xaeDu0/soxURjRuejBJsNyVfo/IpeJ/RT5tYLAv\n" +
            "j66BIA7cZXvgPqb7pagstnl3Zi9wqwVc0En/aWz7enUCi9NMfAvKfgU3dD5/1MFv\n" +
            "AUwlcPCDnVjVhm47R7Tqae60k/NsS70GHBep7O8xirnERPLK0L/5e2zA0+FSyatA\n" +
            "IS+lAxNvTN6wlwLd9FueAM+ZT99cCf/GT16Q8I/nfVzXeqmXtPxDr/2av2Jrqpvr\n" +
            "mmbOTjI6iq0Mb2R360+wz/VOLve0ewgMqIl5GRGWIjou2tg7eojWpN/UcXQwIHwK\n" +
            "TZ0bi6KD0cqbgsx2UATxU/DQNSJG7p4b0Nx3aJxTUkgCEbDJgnxXpwu+tKOUMSwB\n" +
            "qQ3WzHuP8hvrYl43lrPR0at3P7d/rHCjK7jpMPMnfQVZq4qZiXBV+04Mr/OmOe19\n" +
            "eOh+Te26Q4XAj+G1QsIzlR6JEH89sWvrIDS4mmncY/K9cJU8jrLuUgatTM2N3IA4\n" +
            "WWNQ1IEARGexnRdpzdatgjHdQHCL2bvm8DHeiYoAGqJrubtHxKhbzF7fXavNw+gU\n" +
            "LCP9UxdlTaYF0Q2k5UgBzcipJtKljpxtGabRnFu9ZTm2AGuBk4rc4CpwN8d1E8VB\n" +
            "lhZQoPo3ParvfdxVilptEg8F76FY5SP9a3x2G9Kloi/gQ8r1DetaKAqet4pXq1EO\n" +
            "TFVG430dCbYbTHyujp1JhLCYF14j3Wdn19YSYGvu6BATj+0XCHHn2XB+NEQZGrGB\n" +
            "WEGZx+FqkDt3shZk+sKmRmy23zdI6zx3AMNw62hMc928Yix5fDNYoDmojPb+KmjH\n" +
            "JrfGY4gM2thMGqY8QBThpHxzZK4GSB4Xr+MECghHXvKO7au3/1XpO3R7kDsQpBAJ\n" +
            "t/vK3FKraiRUp5Lf7QzTOh6y3OZAT9++4/1Ww6T7NaaQUVKd3dqAc/CB6LL2+tBN\n" +
            "Ee5IHeZeNwslPcRYuDeW/ljF5P1EgXhQB+0udEuZARXInr8Izze1/RU+Y1nwgT8B\n" +
            "HREOjcHzO9+VD89lUTKRLGrlHpC4//3uiP/PZTIuqjfKMXWwdLb7gbwYfud3icag\n" +
            "zANi1N+s7o6SPRh8EjnmAnhIdv3KRv+kXurRqJ/KVXjF71r33aGfg9l3d+25ke+h\n" +
            "zt7jEmioXNz+JZOwmQ3Z0l+5cqwOrxSuSWmzun0=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_KEY_LENGTH));
    }


    [Fact]
    public void Allow_key_too_large_no_maximum()
    {
        // 8192 Bit Key
        // CN=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIJeTCCBWECAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIE\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAwZPi+tCoTBT2TQ2lu2FTVuZ5\n" +
            "Mli5r1fwPH2Pvymja0RGtspOu5vCWAMi5esyTJka/PfU/kgBOuDMzMRWepyHwMlN\n" +
            "shVWEDNKzYT7GcnELzgKFKBfbiiVvPshXEzr13cT+lKyioihrL5g1ksOV+NqSm4+\n" +
            "Iq6KOPRTxcqvJT5G96mVZ3TsfcQKB2OlATzo8DHXVqPS9dM6hnnMbOK2l7ohg1Q4\n" +
            "XC5zzmR1diajzrsFECGTjJRljxm2gtlth3aZXSE4Ep9FQxcc0/BBWMaltMHyeqaF\n" +
            "3a/g4+KjCtRrMeK+NIiJFHxIVlroclY8s59lu+ekqsSoq/vU8nLpRQV5R0D8ER0a\n" +
            "Lmx/tlRT4PiX1W6dbe0rqQGcF6vi8vmaKhcrc60suUex/5CP0i+bDfhkmU0x/s+y\n" +
            "khcr0+yl/FnUOAPLMSerYQZfQVYaZeTK7/bWi+5jySVjagZM752mf8KKWDFqavZU\n" +
            "tDlEu3wZA+kI7ziZsurT8dy8IhRE5QGSLYFExXj2W+D9N4IZZObPGeALc2N50Q1F\n" +
            "dznOwdXVyTlAhGbGvF67/FAdPs0HXBRSiRxogSwcDDdVw9wp0aXySaA7rx55agqR\n" +
            "04WBoSg6ELW3se4M+/EAU2dnC6BB6QLV7gcwGk8+9S4GHL8TguaecYrQwreqMBi9\n" +
            "JhVSa2HgsNBOxLySkAm9UCihlVyk6suPrOF6yE+PRuyPAd2bTbQrBUhm8JNGLWFC\n" +
            "NXvLHN+LOzxBxe3v5npkq/L/CUIPxBuuAuq1OjMsfzfWo5iCZx7R/0SCJbu9c2Ay\n" +
            "MxA3/NeFUF1kNkj7+Y8qUCq8EUvZp8INJBiVCfD/G5kQO4SD0/XZWVqGXs8La0A1\n" +
            "Yk53+Ez7PDLGmC35cA6oO3rFNZAsVZT+EON5t3JWrIt0+RhwQhdNbXtsd2pnewmz\n" +
            "CneCh+hn1iglqO/QpDEg6hXYx8lkwy8vjqrO4rjrwbMJYwZDmRam/eweap5/boBr\n" +
            "nttYrYagjhw/BHBd5aFb1Mk+0rbRd2w08LObC1gdjJxgOi+fc3Z1r8Hn+Bd7GeID\n" +
            "V5Sp3H+2qUdeHiuui/7fwCA/pIT2siWefBH7HZ3eMip9wx7Mm4q3mv4Ie9jyEShg\n" +
            "D+lx1IlTgf37Byq2NhsC9Ph7kdLFW1iAojyZ5UTLugGm7JKruybXcRITBFDTXQsB\n" +
            "0cQ3i+JsBxC9xX4/u9Ph/wH9QiX0h5hwzSY5S2IfjYeeXfiCEG7lKgR0UpqKPWrZ\n" +
            "77eTWXwoSdjzfBqDu3TjXsdwRDbrxOk/iVeC+tN4h/cjJdBB4OOAdHFRFHKobqoU\n" +
            "KFGJD6NpdUklRu9K1M95M4wh+Qe7QJjYKvTCuMzW34v11A7htDsDMtk9lDggQQID\n" +
            "AQABoIIBEjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTgzNjMuMjA+BgkqhkiG9w0B\n" +
            "CQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU7qxAt+UX4mKIM29ua/1t\n" +
            "zw5Y1kowSgYJKwYBBAGCNxUUMT0wOwIBBQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFi\n" +
            "b3IuZGUMCklOVFJBXHJ1ZGkMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcNAgIx\n" +
            "WDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABL\n" +
            "AGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJKoZI\n" +
            "hvcNAQELBQADggQBABqsWv1ziFWM2QHMU5Rz/WqTT6Aw26RyQpzBXoJWaMnzbdKz\n" +
            "4RdXbe+9wNkJ3JGOlOSWpCLkX4P7/GlH1Y0PGpdstyOWIvAra/DM2Aea+aQj0tN7\n" +
            "m7Kah0VtyPwHyFi8V5P9BCJnm0LpeIwdI6ar1tKeLfhSWFnKR+jiCKg+Os8K8ZjK\n" +
            "Y9170FdR8VgYqqnRTHNl1sep9xaeDu0/soxURjRuejBJsNyVfo/IpeJ/RT5tYLAv\n" +
            "j66BIA7cZXvgPqb7pagstnl3Zi9wqwVc0En/aWz7enUCi9NMfAvKfgU3dD5/1MFv\n" +
            "AUwlcPCDnVjVhm47R7Tqae60k/NsS70GHBep7O8xirnERPLK0L/5e2zA0+FSyatA\n" +
            "IS+lAxNvTN6wlwLd9FueAM+ZT99cCf/GT16Q8I/nfVzXeqmXtPxDr/2av2Jrqpvr\n" +
            "mmbOTjI6iq0Mb2R360+wz/VOLve0ewgMqIl5GRGWIjou2tg7eojWpN/UcXQwIHwK\n" +
            "TZ0bi6KD0cqbgsx2UATxU/DQNSJG7p4b0Nx3aJxTUkgCEbDJgnxXpwu+tKOUMSwB\n" +
            "qQ3WzHuP8hvrYl43lrPR0at3P7d/rHCjK7jpMPMnfQVZq4qZiXBV+04Mr/OmOe19\n" +
            "eOh+Te26Q4XAj+G1QsIzlR6JEH89sWvrIDS4mmncY/K9cJU8jrLuUgatTM2N3IA4\n" +
            "WWNQ1IEARGexnRdpzdatgjHdQHCL2bvm8DHeiYoAGqJrubtHxKhbzF7fXavNw+gU\n" +
            "LCP9UxdlTaYF0Q2k5UgBzcipJtKljpxtGabRnFu9ZTm2AGuBk4rc4CpwN8d1E8VB\n" +
            "lhZQoPo3ParvfdxVilptEg8F76FY5SP9a3x2G9Kloi/gQ8r1DetaKAqet4pXq1EO\n" +
            "TFVG430dCbYbTHyujp1JhLCYF14j3Wdn19YSYGvu6BATj+0XCHHn2XB+NEQZGrGB\n" +
            "WEGZx+FqkDt3shZk+sKmRmy23zdI6zx3AMNw62hMc928Yix5fDNYoDmojPb+KmjH\n" +
            "JrfGY4gM2thMGqY8QBThpHxzZK4GSB4Xr+MECghHXvKO7au3/1XpO3R7kDsQpBAJ\n" +
            "t/vK3FKraiRUp5Lf7QzTOh6y3OZAT9++4/1Ww6T7NaaQUVKd3dqAc/CB6LL2+tBN\n" +
            "Ee5IHeZeNwslPcRYuDeW/ljF5P1EgXhQB+0udEuZARXInr8Izze1/RU+Y1nwgT8B\n" +
            "HREOjcHzO9+VD89lUTKRLGrlHpC4//3uiP/PZTIuqjfKMXWwdLb7gbwYfud3icag\n" +
            "zANi1N+s7o6SPRh8EjnmAnhIdv3KRv+kXurRqJ/KVXjF71r33aGfg9l3d+25ke+h\n" +
            "zt7jEmioXNz+JZOwmQ3Z0l+5cqwOrxSuSWmzun0=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.MaximumKeyLength = 0;

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
    }

    [Fact]
    public void Allow_commonName_valid_ECC_key()
    {
        // NISTP256 Key
        // CN=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIB5TCCAYoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMFkw\n" +
            "EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEOCI+dwMwFiVag2RMSiSbJZaMYpQWwjOG\n" +
            "M7DNAb/lwfuj8/iHwD65zVmOOo8bI718nG1K+rrL/pQM1oARFRTfX6CCAQYwHAYK\n" +
            "KwYBBAGCNw0CAzEOFgwxMC4wLjE5MDQ0LjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNV\n" +
            "HQ8BAf8EBAMCB4AwHQYDVR0OBBYEFMBnQ3exgZqATetKob7bmZ2c4LFHMD4GCSsG\n" +
            "AQQBgjcVFDExMC8CAQUMCm90dGktb3R0ZWwMDk9UVEktT1RURUxcdXdlDA5wb3dl\n" +
            "cnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
            "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
            "UAByAG8AdgBpAGQAZQByAwEAMAoGCCqGSM49BAMCA0kAMEYCIQD2DC7IZUOeTAo0\n" +
            "+MK1AfT+JXL2vMrefDpJFTryK398lQIhAJe4wTQP2xpOVAtjPRUcaftqsl9fVOum\n" +
            "pMl8kKH3yqXI\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.MinimumKeyLength = 256;

        var template = new CertificateTemplate
        (
            "TestTemplate",
            true,
            KeyAlgorithmType.ECDSA_P256
        );

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Allow_commonName_valid_ML_DSA_44_key()
    {
        var policy = _policy;
        policy.MaximumKeyLength = 0; // any

        var template = new CertificateTemplate
        (
            "TestTemplate",
            true,
            KeyAlgorithmType.ML_DSA_44
        );

        var dbRow = new CertificateDatabaseRow(_request_mldsa44, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Allow_commonName_valid_ML_DSA_65_key()
    {
        var policy = _policy;
        policy.MaximumKeyLength = 0; // any

        var template = new CertificateTemplate
        (
            "TestTemplate",
            true,
            KeyAlgorithmType.ML_DSA_44
        );

        var dbRow = new CertificateDatabaseRow(_request_mldsa65, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Allow_commonName_valid_ML_DSA_87_key()
    {
        var policy = _policy;
        policy.MaximumKeyLength = 0; // any

        var template = new CertificateTemplate
        (
            "TestTemplate",
            true,
            KeyAlgorithmType.ML_DSA_44
        );

        var dbRow = new CertificateDatabaseRow(_request_mldsa87, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Allow_commonName_valid_dnsName_valid()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // dnsName=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDkjCCAnoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3GmfcSDSunQ6+vmz9mTHcEKg\n" +
            "DMzDSXj0lQ7Erazl9CJ4WzROZaa1BUITfRlVXreku6ljYsO3jyTDBRBtCUXNwFk+\n" +
            "MTmzTqXx82MRpK2ATDp2jEPfP7l7K30DwDyiapkpaAvZlxIVWtIDoGxAG+yRFjAF\n" +
            "Qh4HDvSaBoaNvwdjZsUcdgOuJQbIwBhto/RB+4L23oT7+8e2GyRMm/bQK2gDvCbV\n" +
            "9SwTwm9gXljth0wuZ8RRkC7MMVIiPaxUH575SUKE7YvHeZ4Hq20Q2XYBSigqNXBM\n" +
            "VCUVCfsBGA18/MR/ZMFSSCIt2KLjkpp5q9gOCibw0oPrGTqUoLtCkLREbMrHbQID\n" +
            "AQABoIIBKzAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
            "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
            "bC5leGUwYwYJKoZIhvcNAQkOMVYwVDAOBgNVHQ8BAf8EBAMCB4AwIwYDVR0RAQH/\n" +
            "BBkwF4IVaW50cmFuZXQuYWRjc2xhYm9yLmRlMB0GA1UdDgQWBBRmh46ij+b3RODb\n" +
            "JXIj5NFC58DFZzBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
            "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
            "UAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBAQAmQ8B9fZ+ewB3+\n" +
            "kDFsJcqeMJ+nbFBcHJKmKfhn9564tiBZayK8kpkTvS1Cjb5C79Yimimw2AqGqdFK\n" +
            "W3+wWPCkFN996GoXFOU+lg3I5Byz3Eq4Vyv/H7RCufC68ezVG5v4EaqE4TsYcfoE\n" +
            "zH8HJu0jKKf+QKj9LpXI+HYLwvQ0Fyz4lr839NMidsPF4AWMpEXs/2OSTjg5qDVj\n" +
            "LKMPzd0wrOea0XWx2fEeibdW+KFi1656J+OIGuYP/q0SaPqYgFey+kOS2KLz+9/r\n" +
            "CA+TvKzFxxgRPAfA0TO7GAuwspV2wLOfXVOxIpG5GkmpxeK0nZvyw9HvxWWNlkgw\n" +
            "kbUQqV43\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Deny_SAN_present_but_no_rule_defined()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // dnsName=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDkjCCAnoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3GmfcSDSunQ6+vmz9mTHcEKg\n" +
            "DMzDSXj0lQ7Erazl9CJ4WzROZaa1BUITfRlVXreku6ljYsO3jyTDBRBtCUXNwFk+\n" +
            "MTmzTqXx82MRpK2ATDp2jEPfP7l7K30DwDyiapkpaAvZlxIVWtIDoGxAG+yRFjAF\n" +
            "Qh4HDvSaBoaNvwdjZsUcdgOuJQbIwBhto/RB+4L23oT7+8e2GyRMm/bQK2gDvCbV\n" +
            "9SwTwm9gXljth0wuZ8RRkC7MMVIiPaxUH575SUKE7YvHeZ4Hq20Q2XYBSigqNXBM\n" +
            "VCUVCfsBGA18/MR/ZMFSSCIt2KLjkpp5q9gOCibw0oPrGTqUoLtCkLREbMrHbQID\n" +
            "AQABoIIBKzAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
            "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
            "bC5leGUwYwYJKoZIhvcNAQkOMVYwVDAOBgNVHQ8BAf8EBAMCB4AwIwYDVR0RAQH/\n" +
            "BBkwF4IVaW50cmFuZXQuYWRjc2xhYm9yLmRlMB0GA1UdDgQWBBRmh46ij+b3RODb\n" +
            "JXIj5NFC58DFZzBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
            "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
            "UAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBAQAmQ8B9fZ+ewB3+\n" +
            "kDFsJcqeMJ+nbFBcHJKmKfhn9564tiBZayK8kpkTvS1Cjb5C79Yimimw2AqGqdFK\n" +
            "W3+wWPCkFN996GoXFOU+lg3I5Byz3Eq4Vyv/H7RCufC68ezVG5v4EaqE4TsYcfoE\n" +
            "zH8HJu0jKKf+QKj9LpXI+HYLwvQ0Fyz4lr839NMidsPF4AWMpEXs/2OSTjg5qDVj\n" +
            "LKMPzd0wrOea0XWx2fEeibdW+KFi1656J+OIGuYP/q0SaPqYgFey+kOS2KLz+9/r\n" +
            "CA+TvKzFxxgRPAfA0TO7GAuwspV2wLOfXVOxIpG5GkmpxeK0nZvyw9HvxWWNlkgw\n" +
            "kbUQqV43\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        var policy = _policy;

        policy.SubjectAlternativeName.Clear();

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Allow_commonName_valid_ipAddress_valid()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // ipAddress=192.168.0.1
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDgTCCAmkCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAssXMb23gWNQPuO2OtHubWSIH\n" +
            "f05rvRfHr4pRmMoI3JFuwnTHs5ho3sLtLu/NOroH5xUAthC/OJoUFOusu/9vlptf\n" +
            "8oPABXvHRCuCsEhdfGB/+p7Wf/FMm+YU9KhwNUM1kt1wQ2XAFKEi11iaF8YkzyQ1\n" +
            "PP8zqRU0UNEXlF1GWgc1DOnOkKKkZS2jE1LQ6yBm+suD++EMGPUH+7OSNDGvtWEM\n" +
            "D9LMhH+vcdYpABJbz7jzjytIXmayEQM4oz8CT/2NfRMzSeMOheDCILJugK43A+qe\n" +
            "BpTfie0LA99vYFIHe4vh7Mxc+FR+aHL3dP3doQnt98a0R14XnNn/uUadA46C2QID\n" +
            "AQABoIIBGjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
            "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
            "bC5leGUwUgYJKoZIhvcNAQkOMUUwQzAOBgNVHQ8BAf8EBAMCB4AwEgYDVR0RAQH/\n" +
            "BAgwBocEwKgAATAdBgNVHQ4EFgQUhkzXt+AAu7HigUpHv45MuccLo/IwZgYKKwYB\n" +
            "BAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBh\n" +
            "AHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMB\n" +
            "ADANBgkqhkiG9w0BAQsFAAOCAQEAb0k413f2rAuTtb3cmS3e0w2jLR71d8+OZZ4w\n" +
            "HN618i5xc/1boSY7p/M5rWRbZp4xdtpwYtUFOsUxuOrZdTjYckY6i834r9xZ9BCP\n" +
            "cw3V0FISgyZ1g5lIkV1rQW2V66ZA3SVyzXoPQQ0AJBMdiudIbFsg1BJ3LwmIjuGS\n" +
            "4TF3unbiVDFNXchtwICznn2OFPWPeGnz37xRiuWK7rheXOU+KHWHaVUpyar8J+5O\n" +
            "RRsjitR+Lgqvm/KYUacA5TARMVhGjPzS4O42VYCGjlMR74YaQi+LH3Vezft5G/Ft\n" +
            "CpV76XuDMJqMk4VrPkh1rLljbGqKzuQzIuCVAPFBhsLCqnHByQ==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Allow_commonName_valid_dnsName_at_maximum()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // dnsName=web1.adcslabor.de,web2.adcslabor.de,web3.adcslabor.de,web4.adcslabor.de,web5.adcslabor.de,web6.adcslabor.de,web7.adcslabor.de,web8.adcslabor.de,web9.adcslabor.de,web10.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEQjCCAyoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4nercj9Ulpkk27qrG1jcDmMW\n" +
            "xIRtHPvXOZKTvkN5JYFP7elCwKUHATcECdNwY9hTKDzompL+cS73L6myuzl2oFCs\n" +
            "R/Yhgwf4IRVUjN15sImi8E2VBe7CLbfFstu0ss4wkbHQqY9W3fMjJ5hC4nlJq1iR\n" +
            "kr4qdpZ4ou/D8vxg7hhVbEivSrZ2F1S6erpMlW82S9LIN/OP5fgYKfsHU3KGzCnd\n" +
            "VD/mB6BFDWk5rOgCrgb+ZtfRyaJBQmADHsIhmdx19ZASrVrj3MCED/Sg0YCsZ6hA\n" +
            "rYBxFupzweAMkXcA3ldOXCybLiVdCRkVX3/MWys2/QQOSo1JemWOQ6udKAW0pQID\n" +
            "AQABoIIB2zAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
            "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
            "bC5leGUwZgYKKwYBBAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAg\n" +
            "AFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBv\n" +
            "AHYAaQBkAGUAcgMBADCCAREGCSqGSIb3DQEJDjGCAQIwgf8wDgYDVR0PAQH/BAQD\n" +
            "AgeAMIHNBgNVHREBAf8EgcIwgb+CEXdlYjEuYWRjc2xhYm9yLmRlghF3ZWIyLmFk\n" +
            "Y3NsYWJvci5kZYIRd2ViMy5hZGNzbGFib3IuZGWCEXdlYjQuYWRjc2xhYm9yLmRl\n" +
            "ghF3ZWI1LmFkY3NsYWJvci5kZYIRd2ViNi5hZGNzbGFib3IuZGWCEXdlYjcuYWRj\n" +
            "c2xhYm9yLmRlghF3ZWI4LmFkY3NsYWJvci5kZYIRd2ViOS5hZGNzbGFib3IuZGWC\n" +
            "EndlYjEwLmFkY3NsYWJvci5kZTAdBgNVHQ4EFgQU+yk1zDDNwJLRaRyZ5F5S0NCG\n" +
            "3NkwDQYJKoZIhvcNAQELBQADggEBAHPuyBtJ+Qfnrd8G3sqDyGqYZrVbeZr9OX5X\n" +
            "frw5witZSgz7miEC8Mk4AsU2yAEllCPgblzVnXakw+bGF4NRm8UoDoODhTLSOlxI\n" +
            "yyTpGzKGWm6PuHzx+99DiueHRZ0SPpQXdg3wCram7wlP3YLpAW4z8DaPkDAs1t3D\n" +
            "s6GFEzzriYHsSCI8xv1O6eQemORKnPP8gqfhWwn8uf9RkHZ2yFDbMMCySwiiFAPo\n" +
            "W0qGy6WU15+a7PlOVcbsC4Bbqy6FGIV6BaZ/Be9OAzDuoaX6p7Wz7hk6y71XZPaP\n" +
            "sicnx80RxPqTLH3kpX+8egvRxSmXt9rX3adVaOnrXvvEzj7kQzA=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Deny_ipAddress_invalid()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // ipAddress=172.16.0.1
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDgTCCAmkCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmpqmUV/QKVRdWY8C8VFl4BZ/\n" +
            "/M/lr0Um8BGgz8Nv4He7XTLjOE5C89D9REMjlY8n6AYE0sb+YQ/23guRwYjTPtNp\n" +
            "V41VFexQraXvRDYSNOP0zJan3mZh6tzOI08J7L38Sp7pSHzVwdK64sdKOvvu+Um8\n" +
            "Z9A02+Y4VDV8BAUrF7HRKcglL2GwK2VqOTr2BW1aU9+jk/FsyTpeORZqPuXHGleA\n" +
            "8vDt1bzWbPnPOmDhV4oCAyo0JfhtXZS4zTmWYtwQpQ9ZG2TypmZvIXX4Q4511Wm8\n" +
            "V5uYRBaeSk5xz+aXMFIUBdyYAnF6LY83MnPK0hZX2AuVAPBLby1OjvmXqwImUQID\n" +
            "AQABoIIBGjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
            "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
            "bC5leGUwUgYJKoZIhvcNAQkOMUUwQzAOBgNVHQ8BAf8EBAMCB4AwEgYDVR0RAQH/\n" +
            "BAgwBocErBAAATAdBgNVHQ4EFgQUynSs9RAoplZqmr4uP3BKf+50qEwwZgYKKwYB\n" +
            "BAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBh\n" +
            "AHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMB\n" +
            "ADANBgkqhkiG9w0BAQsFAAOCAQEAFyj/YGtMuPT4oHfHw+mM4h83qM1kHSj6SFGe\n" +
            "BtLgX0XnC6k1oFsRk7eiQ4Lf4d6FKJhGVE+STkqPk1Mxfj5GPV34kXp8PXwQUPjw\n" +
            "PB9HosGZWRgPH03kkCvq/mvmzKSk3fkwMfhHJABLlQYlbEx0ZFpgfU7atNjshLOz\n" +
            "uwzV7kNpXL3xLjI/kIgCzr2UMSfNlF+Gv5qwT/RDzNSr+F3GIFNfx7PJmP/M/lNa\n" +
            "5MW7LkWEOpJFAGxW4g2ssGITQXHCvfcL0sIp4o1KzUMiXwgaMrdtj0ON3s5iqtVS\n" +
            "zplTRSF8Tgfw0i/iblG5Ap4RhcD5wsvLYF1VeTsWKmt2hhNzyA==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_ipAddress_forbidden()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // ipAddress=192.168.0.1,192.168.123.1 (the latter is blacklisted)
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDhzCCAm8CAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs4uQyl+JHKtQuADVbbtpw3g8\n" +
            "W9obkgaQWXiQA5k9mM3zJnUJa9HXfLGAy3x1X5biu6/8F8JdzMOETfLCH7lmNIxq\n" +
            "qWP94UgbE2C5+LcZaWG9C/ne59icLdX1gnrwwNbRYpAkq46f6z9pViyYpuJCBmXn\n" +
            "NkTbhsONLHPCwvLyYEG9cW31mPh3YQ/rEnAoB7BWiPByJPu26GZdo7NcJs+ZvehV\n" +
            "+uBPH8kL7/M5KAQdplKFlCbZvaGZSOBXNX6EAqkG1kbCSoQDUCe8tL0XXSiqf4l8\n" +
            "40IZ44xn+TeuhmczE6jyXxvOOyQipqS+eiV4/4+R7E5Mg58EUvRIg+aXgy7wcQID\n" +
            "AQABoIIBIDAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
            "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
            "bC5leGUwWAYJKoZIhvcNAQkOMUswSTAOBgNVHQ8BAf8EBAMCB4AwGAYDVR0RAQH/\n" +
            "BA4wDIcEwKgAAYcEwKh7ATAdBgNVHQ4EFgQU7yUp75Tjkkw9vuMo3ARZRlURr4gw\n" +
            "ZgYKKwYBBAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBm\n" +
            "AHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBk\n" +
            "AGUAcgMBADANBgkqhkiG9w0BAQsFAAOCAQEABSTtKWbLXwn9PGmPYQhSNgR1c4xJ\n" +
            "7AvqivmLbUspCIxzgCGx2gKsglME0D8OUr94bgRXCecVEA92o4Ev9AR0pCPF2jx6\n" +
            "6l+GpK1sjf2hrqU+Gp/MmJd7dvZk/L1co97oFNgC/3H66Mv0A/ohtGY0W01/MSnB\n" +
            "x5vdsf6apO5Gnvq+PdDGCb1qTFvjgZzvpALWOY2835k8PIY3CndBh7Ov/XZ2Tvr/\n" +
            "nY1BCWuu0d50Qm8hhVYOoVKP15vvqcr/UD2nlUY9Gv9kuScmmPi3q5QeK01kI4EV\n" +
            "bgfsnA7boakcA8eeKvCSXfdRdHrRFhSECwFLp7yu/m90XE9FIOYIzBVZeQ==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_dnsName_too_often()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // dnsName=web1.adcslabor.de,web2.adcslabor.de,web3.adcslabor.de,web4.adcslabor.de,web5.adcslabor.de,web6.adcslabor.de,web7.adcslabor.de,web8.adcslabor.de,web9.adcslabor.de,web10.adcslabor.de,web11.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEVzCCAz8CAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzG+t/h3Ah19iL5Jv58Psr0EX\n" +
            "vV5nxtdKdBdpU7Yin0ya/etDFXX9tkg8HHk07OcWdYvqwtifxHCNI1Jf4Z/+e6Va\n" +
            "S+cQniOMszYoF07+JbqcFJv2aZVnKZSIJUH1qzyd5KR/mNCzFIFUqxEdZusr4yS+\n" +
            "rSlVCqD55YIbF/wlpWdEucLVx6g0DdQdZkaArQTr8WeuLNrEPCSl7I0ERr7GciWn\n" +
            "Z0boJysodza9t6d3JnfES62EQzRsYTw9qJaEwo4gdyNMZgYAT1xjImNhKeZywn9L\n" +
            "auKM72VwyTQEEkkDaQcpCS1u9iq53y4eYnGuJsXMG7DSPnz3C6O/msriuOQtxQID\n" +
            "AQABoIIB8DAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
            "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
            "bC5leGUwZgYKKwYBBAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAg\n" +
            "AFMAbwBmAHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBv\n" +
            "AHYAaQBkAGUAcgMBADCCASYGCSqGSIb3DQEJDjGCARcwggETMA4GA1UdDwEB/wQE\n" +
            "AwIHgDCB4QYDVR0RAQH/BIHWMIHTghF3ZWIxLmFkY3NsYWJvci5kZYIRd2ViMi5h\n" +
            "ZGNzbGFib3IuZGWCEXdlYjMuYWRjc2xhYm9yLmRlghF3ZWI0LmFkY3NsYWJvci5k\n" +
            "ZYIRd2ViNS5hZGNzbGFib3IuZGWCEXdlYjYuYWRjc2xhYm9yLmRlghF3ZWI3LmFk\n" +
            "Y3NsYWJvci5kZYIRd2ViOC5hZGNzbGFib3IuZGWCEXdlYjkuYWRjc2xhYm9yLmRl\n" +
            "ghJ3ZWIxMC5hZGNzbGFib3IuZGWCEndlYjExLmFkY3NsYWJvci5kZTAdBgNVHQ4E\n" +
            "FgQUXGUqf/a7LAB9cGx2EL/kKDfabXQwDQYJKoZIhvcNAQELBQADggEBABiXYOA5\n" +
            "F3imZ1jlmI3HlCiYBU6rDXn70MygPdszcIVmXAksCuADdLQcWZb8AeG3ywmbNFgu\n" +
            "x+HJWMpDrxTbPaKf/1Svk18pT329W5nppjxy3AGaUW6Bx8Yqnrw03u36oSM44pKg\n" +
            "tyl9hTzl/8+YvYzLl4tAvXKPMhtUI6rQZ3tRRak01xKchlMgEknEDMx6gHZ3zaRS\n" +
            "KqlX2MaUSzrffubkUdccoMrDsZgIEj541H1/3VbbkNDrQfgAuxrk0ivgkFXOI02L\n" +
            "v4eWHL0lwaS5Bk08EwHFj2FLuzCeHF15UbmaDQzJ9wj43Cn7+H82X3QQ+v0TDXPr\n" +
            "C6bmuhV2Gm14AnY=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_Subject_RDN_too_often()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de,CN=extranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEjTCCAvUCAQAwQDEeMBwGA1UEAxMVZXh0cmFuZXQuYWRjc2xhYm9yLmRlMR4w\n" +
            "HAYDVQQDExVpbnRyYW5ldC5hZGNzbGFib3IuZGUwggGiMA0GCSqGSIb3DQEBAQUA\n" +
            "A4IBjwAwggGKAoIBgQClf+SLosrRPwLQAv506dNTA2O7dSUndsTwzp3kE3w9XM1p\n" +
            "mD4C51a+yqFQ6bVjns1zv/R4EiFdI1TG6J6iYb2p4QFw+apD9kwsMJ+rVhMCR+iN\n" +
            "XGFSMeBqHcRQ1UzWOYqEqiKGHMaYVKw18b8zweExQFPUKc+BediroJwjkyiOnjNJ\n" +
            "300PyW1urGeeukpcofcqPrq+oiBFbxrjfMVGZZ6h0dc8dPd1opCQxDPp5ozUVs0c\n" +
            "FdJQhM/q0woX8Xn1IH2cmTWTPS3+0HcBuA+6DBwGPcKTTCcHSgj31BD/K5ao8NTJ\n" +
            "vUxWDo5h+1wzGFyFwjPWaoY8mNro3deMr0xZgVDnKQ111Ez16dM1ID1MPv0z3/xq\n" +
            "Ks9klfZuKcxz8gPMSYiRFh2AahOhccckLphQQvyNMVW94jsVc+glMXvSl0unb4CJ\n" +
            "9xsOrCedmfx9t+q5Y4GTF6EiJNR6bzcH9orIAaAa294CNT4XflqRYW5Hscgo9F7Q\n" +
            "aG7QQbeIXuL1RpksfWkCAwEAAaCCAQYwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjIy\n" +
            "NjMxLjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYE\n" +
            "FAbGtMxnZvfqTwkAZ4sPOCPB8E57MD4GCSsGAQQBgjcVFDExMC8CAQUMCkxBUFRP\n" +
            "UC1VV0UMDkxBUFRPUC1VV0VcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3\n" +
            "DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBl\n" +
            "ACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0G\n" +
            "CSqGSIb3DQEBCwUAA4IBgQAPAXa0K4dR1vMo5O8WQ4/0Emm98CkHVP8JuGFniYIk\n" +
            "lV5oJomLR3judj+Dife52OCk1Qb889R3uVNou3rhhqQA+tlPHjGjO/UJP4p4E1E9\n" +
            "ZjuyKXMhZS7B9S64dbmeKA5dF48a0L/TDeGpKb8Oypz/kfvdq8F4kLdTu5iPjcIU\n" +
            "Z+PxPgEeEp8nMB8wTIQCwpKSFLFez2demQODenqaJnmy02MX9tC0awkKxyidUYVI\n" +
            "5k6pfjxVi2ZMLkOTTpBvgC+fLGd/c9GtPHa9DoewHoBTeRntD2e1gKRmHc6Rz1+3\n" +
            "A1C/PooSy2bn9M+ueEDbhVuOodQwVBlBw/0beG0iuwab93XtQCkW7C2Z6j4VSITY\n" +
            "QWyxarUJfIpb5K+9dJgXvo0r9ffwxuyNx5XZ/aZijfuw3vvzcblZsMmIJiO6+yQn\n" +
            "JboGWSyOZeAx4g4bYH07N/49Q3bAkEPYIBb9wjWWSngjF+9CgaMGtXjECBrpWrNq\n" +
            "/H61T5lzfmEDPUg8TDWX+2w=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Allow_Subject_RDN_more_than_once()
    {
        var policy = _policy;

        policy.Subject.Clear();

        policy.Subject.Add(
            new SubjectRule
            {
                Field = RdnTypes.CommonName,
                Mandatory = true,
                MaxOccurrences = 2,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"^(intranet|extranet)\.adcslabor\.de$" }
                }
            }
        );

        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de,CN=extranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEjTCCAvUCAQAwQDEeMBwGA1UEAxMVZXh0cmFuZXQuYWRjc2xhYm9yLmRlMR4w\n" +
            "HAYDVQQDExVpbnRyYW5ldC5hZGNzbGFib3IuZGUwggGiMA0GCSqGSIb3DQEBAQUA\n" +
            "A4IBjwAwggGKAoIBgQClf+SLosrRPwLQAv506dNTA2O7dSUndsTwzp3kE3w9XM1p\n" +
            "mD4C51a+yqFQ6bVjns1zv/R4EiFdI1TG6J6iYb2p4QFw+apD9kwsMJ+rVhMCR+iN\n" +
            "XGFSMeBqHcRQ1UzWOYqEqiKGHMaYVKw18b8zweExQFPUKc+BediroJwjkyiOnjNJ\n" +
            "300PyW1urGeeukpcofcqPrq+oiBFbxrjfMVGZZ6h0dc8dPd1opCQxDPp5ozUVs0c\n" +
            "FdJQhM/q0woX8Xn1IH2cmTWTPS3+0HcBuA+6DBwGPcKTTCcHSgj31BD/K5ao8NTJ\n" +
            "vUxWDo5h+1wzGFyFwjPWaoY8mNro3deMr0xZgVDnKQ111Ez16dM1ID1MPv0z3/xq\n" +
            "Ks9klfZuKcxz8gPMSYiRFh2AahOhccckLphQQvyNMVW94jsVc+glMXvSl0unb4CJ\n" +
            "9xsOrCedmfx9t+q5Y4GTF6EiJNR6bzcH9orIAaAa294CNT4XflqRYW5Hscgo9F7Q\n" +
            "aG7QQbeIXuL1RpksfWkCAwEAAaCCAQYwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjIy\n" +
            "NjMxLjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYE\n" +
            "FAbGtMxnZvfqTwkAZ4sPOCPB8E57MD4GCSsGAQQBgjcVFDExMC8CAQUMCkxBUFRP\n" +
            "UC1VV0UMDkxBUFRPUC1VV0VcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3\n" +
            "DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBl\n" +
            "ACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0G\n" +
            "CSqGSIb3DQEBCwUAA4IBgQAPAXa0K4dR1vMo5O8WQ4/0Emm98CkHVP8JuGFniYIk\n" +
            "lV5oJomLR3judj+Dife52OCk1Qb889R3uVNou3rhhqQA+tlPHjGjO/UJP4p4E1E9\n" +
            "ZjuyKXMhZS7B9S64dbmeKA5dF48a0L/TDeGpKb8Oypz/kfvdq8F4kLdTu5iPjcIU\n" +
            "Z+PxPgEeEp8nMB8wTIQCwpKSFLFez2demQODenqaJnmy02MX9tC0awkKxyidUYVI\n" +
            "5k6pfjxVi2ZMLkOTTpBvgC+fLGd/c9GtPHa9DoewHoBTeRntD2e1gKRmHc6Rz1+3\n" +
            "A1C/PooSy2bn9M+ueEDbhVuOodQwVBlBw/0beG0iuwab93XtQCkW7C2Z6j4VSITY\n" +
            "QWyxarUJfIpb5K+9dJgXvo0r9ffwxuyNx5XZ/aZijfuw3vvzcblZsMmIJiO6+yQn\n" +
            "JboGWSyOZeAx4g4bYH07N/49Q3bAkEPYIBb9wjWWSngjF+9CgaMGtXjECBrpWrNq\n" +
            "/H61T5lzfmEDPUg8TDWX+2w=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Deny_dnsName_forbidden()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // dnsName=web1.adcslabor.de,web2.adcslabor.de,web3.adcslabor.de,web4.adcslabor.de,web5.adcslabor.de,web6.adcslabor.de,web7.pkilabor.de,web8.adcslabor.de,web9.adcslabor.de,web10.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIFQTCCA6kCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEArXgJYDmOKoK+GJ5AhPzYqBgi\n" +
            "ROXPhhxnriC/ImMF+FrQeTwAyVPS5zEAtuxYxFR9Kg/W7ob0qW6zoyKWkNxjzimp\n" +
            "DrJGX2M/g8PSyNnbExFFz6FiSZu0hM976oWRdzO3bBDyaWnuef8SM0YS9EWAzhOd\n" +
            "Yi16eboyRdAmi2nbwpVSG+idAz4R5LNAyGvl71PHHE0U+T3SccZdY81grGENXtNO\n" +
            "UOZ8Mb+5b5tNZLxIPsBdR24bvu3eNjQQmfzJcTjab0In091QRagX3cV7XOWN7C3f\n" +
            "kL0g0PePwJ3ILI6olqS1FpCKGb3PDKW/MCI/ekzBUItA+n4Kp+T+fZK//OmKBJpK\n" +
            "XI+bUjSKBcJIeAyvziceD/SgjQwRrH17L9ETcaM1Vs22cKLmdFrl0bCi8EEfyzzr\n" +
            "vBCJUKB9zEUYp5oK2kUmQIq+HBeLA1lyPz52fVb2+SeX0BWl6D6VZzf+mNdrDRq2\n" +
            "mMHzjBoU0wbLMtYVX8bH7c573aq2rLTWw4ILvtFdAgMBAAGgggHaMBwGCisGAQQB\n" +
            "gjcNAgMxDhYMMTAuMC4xOTA0NC4yMD4GCSsGAQQBgjcVFDExMC8CAQUMCkxBUFRP\n" +
            "UC1VV0UMDkxBUFRPUC1VV0VcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3\n" +
            "DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBl\n" +
            "ACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMIIB\n" +
            "EAYJKoZIhvcNAQkOMYIBATCB/jAOBgNVHQ8BAf8EBAMCB4AwgcwGA1UdEQEB/wSB\n" +
            "wTCBvoIRd2ViMS5hZGNzbGFib3IuZGWCEXdlYjIuYWRjc2xhYm9yLmRlghF3ZWIz\n" +
            "LmFkY3NsYWJvci5kZYIRd2ViNC5hZGNzbGFib3IuZGWCEXdlYjUuYWRjc2xhYm9y\n" +
            "LmRlghF3ZWI2LmFkY3NsYWJvci5kZYIQd2ViNy5wa2lsYWJvci5kZYIRd2ViOC5h\n" +
            "ZGNzbGFib3IuZGWCEXdlYjkuYWRjc2xhYm9yLmRlghJ3ZWIxMC5hZGNzbGFib3Iu\n" +
            "ZGUwHQYDVR0OBBYEFLHzMISFNmmMU/xchafRVXOY1GnwMA0GCSqGSIb3DQEBCwUA\n" +
            "A4IBgQBAX2dAWlfNd+9KRS06QvNFLKfaRrRiYIPVVe5K+wevkgNquV5Sf6quVX64\n" +
            "xkHpAUU9GWB4CFrwXE0KbouBozLhKvamjg1Ndl7ZxGolnCGfPqReVVpKJ9WViGrY\n" +
            "SxqMMvX+jJY1L/Res5SwnboiNIRYS3z/hoQiMs9dqvzR1gs92ygIHxhDNroYd1O8\n" +
            "9gIZ7TGnV07r4WWut6GLA9ljDPPsx6nj1kOB4yQFNHCfrrzcUXpThXdhL1nrOIJY\n" +
            "2px38RuAPHh47AKP17uTwEvkdIX5hh0g8mEdyTqzoTpJfkl49Q4eCRWhJYvSvWqm\n" +
            "vWvQWzxyN7rFyonbOya6uU8M4uhLm4hKkfscC4KUtukfIli3X6KxPupEEmbFUXZZ\n" +
            "2GZLqPeJ1xiOtsglTQ+uYNvwelQk+B8fPgX0ouvduEeJldQ48I8+T4Ni9wUmtm9H\n" +
            "B5takWnKYdzvkFi5cEPGpK+Qe08vN5Lg7w9QK0/8vJfk6hvc/mk2qnECvOsJQuug\n" +
            "gIECro4=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Does_supplement_DnsName()
    {
        // 3072 Bit RSA Key
        // CN=www.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEaDCCAtACAQAwGzEZMBcGA1UEAxMQd3d3LmFkY3NsYWJvci5kZTCCAaIwDQYJ\n" +
            "KoZIhvcNAQEBBQADggGPADCCAYoCggGBAKxQ0z/cnnbYS6sipgyb04k54QLS9B2I\n" +
            "jQ5xMjJllPn1iFjWy4hzWvRyfFdt1u9M2TKOjoey25xYdllcAqSzfcZNsgEwl6qD\n" +
            "x1vt+psquY8yv0zZvj3HQDre6st3SNztyne5WgB6Hbx3j1qznnGFhnuw+F8nthSu\n" +
            "0kJfgjNEbxWWHfdq7iViQTmHNKGJcA0kIelq7/Nv5ipj/ruKgHGAvqcX4Ak5j+R2\n" +
            "t3VVQhXj/lmoVO1IlhK3iep0btBOhrSCDS/g9Pd6FpdMZ2M0A9Nr1ocEhYqatSQ4\n" +
            "jknOzvkwgTM9w/UD8ia5bWMXIDeibn0wHKTJWfG+2+eq5TFiYoMJoFVsW35ZAtlb\n" +
            "Kp+jXbWU/NAsiJ4Z8Pbq04wViBrIf1xQ4wSgCibMF6NmO+tyI+1h2cJPU42uZs3y\n" +
            "NGdqutG4/6qEoi+OzfvhgAU1u0Rc8fUC2B9s8kH0SkDZPP0cruW0G97Cmjlx9J0k\n" +
            "EdFhmNkePMp103LWavkw2qGetB4nQpw5KQIDAQABoIIBBjAcBgorBgEEAYI3DQID\n" +
            "MQ4WDDEwLjAuMTkwNDQuMjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIH\n" +
            "gDAdBgNVHQ4EFgQUfnzkcusRKrp6YKuR1rLou96hlzcwPgYJKwYBBAGCNxUUMTEw\n" +
            "LwIBBQwKTEFQVE9QLVVXRQwOTEFQVE9QLVVXRVx1d2UMDnBvd2Vyc2hlbGwuZXhl\n" +
            "MGYGCisGAQQBgjcNAgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8A\n" +
            "ZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkA\n" +
            "ZABlAHIDAQAwDQYJKoZIhvcNAQELBQADggGBAD+rFHnJrPY3g5QjxSGoJ2Xi1CCj\n" +
            "ivxz7ePx6nsAeF9TWU/rjIrGlf9/vI8eNiVvJNiJKaBA3UZVCgkfFmfB4OrkeQ9O\n" +
            "4bEYBcF5uEKAq0NP0MfGgHUk/bpj0YdnYM459rtk4vBBQ8zeV2mP2U0cjj2T5uz5\n" +
            "eAc2fCGlxyz/9U7XSRFPrPIOHV8eDaVdaF7ip1sxGHxGLuf+OkcQT9VVhw0J9iSE\n" +
            "JJWGf6NMl4vEfUyF9tsfI55aIr3RbV7612xhrwJPncCsdRBLGZZ0O6TF0FfpOBhu\n" +
            "kWvY/w+pjUMF2oPgjWiKCbcIHyW53faoM4PFaI0uZ15Umwc91W97OcOVuY2g182Q\n" +
            "v39Vt9uB7wMZNerZuhD/r05UOxXCLZ9L0wYc/dljmquBb1M7hbGfGTAbai8TjZYd\n" +
            "/uaXsaIZ+/Anrn6wKOTb3N4IrKhnct/QcFbU5OWLHd7rX2CRItrHps+I4EZwXovl\n" +
            "2iSQrc43rVBo13Z3kdSA0fwTvVPSiOFWof5stg==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;

        policy.SupplementDnsNames = true;

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);


        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(
                    result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals("MBKCEHd3dy5hZGNzbGFib3IuZGU="));
    }

    [Fact]
    public void Does_supplement_unqualified_DnsName()
    {
        // 3072 Bit RSA Key
        // CN=qualified.tamemycerts.com,CN=unqualified
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEhzCCAu8CAQAwOjEUMBIGA1UEAxMLdW5xdWFsaWZpZWQxIjAgBgNVBAMTGXF1\n" +
            "YWxpZmllZC50YW1lbXljZXJ0cy5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw\n" +
            "ggGKAoIBgQC5nstgs9tW3aBa4mfmbw9i28inu9y3UtfZ0dsB2dzCdiWDPyctrAjR\n" +
            "IVDmPFSc3osI79KQGBYi6TtBLbILXcLLDhYjkgv/1hnZq6yBx9G5S8jNnQLF9utG\n" +
            "QNRfVpfxMcKK2PN72VSf9YZC+4Eye9yvEO8pjTjcg0aOYBflmNrfBlT3ERQgDOE7\n" +
            "xHt5/05QI1CIJ1b57JPtciDh2ptS21nyZWchnTC6SF+YDuH633SbQrdv61w7xeKi\n" +
            "GS6wx/trOKvpE5xwzaNEVX6ZENd6W6RUCR0xRuoRrzQmBQawwt3V0BL9cGjd6RJq\n" +
            "XKNDKD+IcB+tS38joEDOYICnQ/3HXcQDgmUJlL1oiwBhIr2f5FE4vz6U6rlMmMus\n" +
            "+BJcaZtpWm3MJG0nDMzh1wgYDp2kwqhR0IjI2q9CTDwLrzuISURRycDQD5tJZmyQ\n" +
            "o+oORVmbIHuCvqUD8DEHExDeSi1PSQAETjlUCEeMo0GFjvj2B7wIltVEgC6CuNC/\n" +
            "GZ0vpIdt1fECAwEAAaCCAQYwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjIyNjMxLjIw\n" +
            "PgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFF5ogirh\n" +
            "7+rKRb59Z1Cw55Dd73cMMD4GCSsGAQQBgjcVFDExMC8CAQUMCkxBUFRPUC1VV0UM\n" +
            "DkxBUFRPUC1VV0VcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgw\n" +
            "VgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBl\n" +
            "AHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3\n" +
            "DQEBCwUAA4IBgQBWr/8PxuFFNwwbiV/q1028ykN6mDpCSwywYkCf7ufBrKGZe50I\n" +
            "xajlXKBhuLpNsEgI+QvyRtANPWo6qOKEIOWFkBsVYvPU/hgcx6EWP4xhhoDnPRbR\n" +
            "4GqWQfXC06+ePSprRntLHS9LbZH9ajpts1WRTAYFBSRuODGaFgmeRCOIKnBQevN6\n" +
            "qM1bVNTTw3C7QtsxZ/q4fZB/+7keLcBcXDjXcD1W1HIT47PwcZQ22rcuEq7kdZRk\n" +
            "TwPfvF6bCIZYlj9T2WqEqkUHhoblLVrmvh8HfZzgNb49NctVGky2R79astD8DjF+\n" +
            "m8lV+hiiMUZlurgVOXj/ePQuWNy9XAEhtzVQ7L+qOnHanO5untAn+7rcE67bK3lh\n" +
            "sFgOJig+BZHPUwuQwLQZ97Ex1oQl6nce1XltZV51TNfi+A/PIRzq2aUX1GxaVpWC\n" +
            "BS+hA0XKTViNhtnmnw//DWY0mzIrPbw5zUZR8jDI8zsVB8rfijgHzzB73hMWPwpU\n" +
            "OJOeF3uo1kWL3oE=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.SupplementDnsNames = true;

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);


        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(
                    result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals("MCiCC3VucXVhbGlmaWVkghlxdWFsaWZpZWQudGFtZW15Y2VydHMuY29t"));
    }

    [Fact]
    public void Does_not_supplement_unqualified_DnsName()
    {
        // 3072 Bit RSA Key
        // CN=qualified.tamemycerts.com,CN=unqualified
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEhzCCAu8CAQAwOjEUMBIGA1UEAxMLdW5xdWFsaWZpZWQxIjAgBgNVBAMTGXF1\n" +
            "YWxpZmllZC50YW1lbXljZXJ0cy5jb20wggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw\n" +
            "ggGKAoIBgQC5nstgs9tW3aBa4mfmbw9i28inu9y3UtfZ0dsB2dzCdiWDPyctrAjR\n" +
            "IVDmPFSc3osI79KQGBYi6TtBLbILXcLLDhYjkgv/1hnZq6yBx9G5S8jNnQLF9utG\n" +
            "QNRfVpfxMcKK2PN72VSf9YZC+4Eye9yvEO8pjTjcg0aOYBflmNrfBlT3ERQgDOE7\n" +
            "xHt5/05QI1CIJ1b57JPtciDh2ptS21nyZWchnTC6SF+YDuH633SbQrdv61w7xeKi\n" +
            "GS6wx/trOKvpE5xwzaNEVX6ZENd6W6RUCR0xRuoRrzQmBQawwt3V0BL9cGjd6RJq\n" +
            "XKNDKD+IcB+tS38joEDOYICnQ/3HXcQDgmUJlL1oiwBhIr2f5FE4vz6U6rlMmMus\n" +
            "+BJcaZtpWm3MJG0nDMzh1wgYDp2kwqhR0IjI2q9CTDwLrzuISURRycDQD5tJZmyQ\n" +
            "o+oORVmbIHuCvqUD8DEHExDeSi1PSQAETjlUCEeMo0GFjvj2B7wIltVEgC6CuNC/\n" +
            "GZ0vpIdt1fECAwEAAaCCAQYwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjIyNjMxLjIw\n" +
            "PgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFF5ogirh\n" +
            "7+rKRb59Z1Cw55Dd73cMMD4GCSsGAQQBgjcVFDExMC8CAQUMCkxBUFRPUC1VV0UM\n" +
            "DkxBUFRPUC1VV0VcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgw\n" +
            "VgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBl\n" +
            "AHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3\n" +
            "DQEBCwUAA4IBgQBWr/8PxuFFNwwbiV/q1028ykN6mDpCSwywYkCf7ufBrKGZe50I\n" +
            "xajlXKBhuLpNsEgI+QvyRtANPWo6qOKEIOWFkBsVYvPU/hgcx6EWP4xhhoDnPRbR\n" +
            "4GqWQfXC06+ePSprRntLHS9LbZH9ajpts1WRTAYFBSRuODGaFgmeRCOIKnBQevN6\n" +
            "qM1bVNTTw3C7QtsxZ/q4fZB/+7keLcBcXDjXcD1W1HIT47PwcZQ22rcuEq7kdZRk\n" +
            "TwPfvF6bCIZYlj9T2WqEqkUHhoblLVrmvh8HfZzgNb49NctVGky2R79astD8DjF+\n" +
            "m8lV+hiiMUZlurgVOXj/ePQuWNy9XAEhtzVQ7L+qOnHanO5untAn+7rcE67bK3lh\n" +
            "sFgOJig+BZHPUwuQwLQZ97Ex1oQl6nce1XltZV51TNfi+A/PIRzq2aUX1GxaVpWC\n" +
            "BS+hA0XKTViNhtnmnw//DWY0mzIrPbw5zUZR8jDI8zsVB8rfijgHzzB73hMWPwpU\n" +
            "OJOeF3uo1kWL3oE=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.SupplementDnsNames = true;
        policy.SupplementUnqualifiedNames = false;

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);


        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(
                    result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals("MBuCGXF1YWxpZmllZC50YW1lbXljZXJ0cy5jb20="));
    }

    [Fact]
    public void Does_supplement_IPv4()
    {
        // 3072 Bit RSA Key
        // CN=192.168.0.1
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEbzCCAtcCAQAwFjEUMBIGA1UEAxMLMTkyLjE2OC4wLjEwggGiMA0GCSqGSIb3\n" +
            "DQEBAQUAA4IBjwAwggGKAoIBgQDIKE0iAutNOSr+LMSXeEYDIE+h7wUDQLVs7wEF\n" +
            "GcsbGoiS/6xAFhY1IN5b0ybs9Y2sgpFU2eGHp+EL1sVNCi2EvQJrxotyk5o6HbiM\n" +
            "xMmsEqQSIPNWwZewKQL/dKMcAY6PHfy8VcSqJ0dOwIoj49Cb3NouDovD2fvDHC6N\n" +
            "2c2sjaOVDl7S4uAlVhDnFpYOQMzfXNHI59veKk5yv0NdSZlhNU1WLltgz6g12l9D\n" +
            "AIZh2JSQ5NvGBTQ5bzc+OH5EnV1s/ZrBBiorYlfdtFOlTGhW7k2Pz2GN85KciEWc\n" +
            "zX3u3Xdt2JwcSA3Tg+UmVW8BSzs8Tq/fIVBaXjnCxWWVI3fttFvHPjNwdQsB2Zso\n" +
            "n0K9M4s9HV1mChHJlWEjRGVFNcdUfEITG47wVD7Xj0/iDnS0r8mGqeQ89UXn63hJ\n" +
            "UvPeLGu2cUDbThD3d4a6SMwC7UXPvS3bF9toDSfW3HdG4L+tXiW1HiqlV/RVfs33\n" +
            "msH7RxTar06wfbvubzPW1G+BQEUCAwEAAaCCARIwHAYKKwYBBAGCNw0CAzEOFgwx\n" +
            "MC4wLjE4MzYzLjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYD\n" +
            "VR0OBBYEFGuhRsZitMLDhxPdUIPZSq2J95zUMEoGCSsGAQQBgjcVFDE9MDsCAQUM\n" +
            "GkNMSUVOVDIuaW50cmEuYWRjc2xhYm9yLmRlDApJTlRSQVxydWRpDA5wb3dlcnNo\n" +
            "ZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0\n" +
            "ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUABy\n" +
            "AG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBgQAuuHIyaWIx8eHCD79h\n" +
            "Qz16OjsyF4h3XBZx+3k9oFZFGj+Dl7d1oY0rtO/C6MJ4pIT1I7QeSD/31Kyd3eQT\n" +
            "MuIT/OL2ExYtwLHkz/M6cQgSxj8NobecNue1cKCGqU8kxRQ7y1W4GAYZBxsI7Vum\n" +
            "M5bvSVnSzzhi4/kLj/wAIaF08ysdDb8zq120KxSrU+ygi/NNcLEAuAEETuXjYpXF\n" +
            "bjdgTPaBju1/Q6IhrS3XC6cRrrUeMH3KOmTgi3Ib9rd+7fOh1oGUpSq5Hk7LZIgX\n" +
            "b3MIXN/99gjy+VJaMNK4k5gS3QO+hWDR9QyStFlW1tcIyCbTsDNJT/ZlzfAmNnEl\n" +
            "R9eacVVSVZXhbf8lQNMwhcsTzNoSYtf1v9lyM2nPB1/4AY8EVox4b3pMAgEqQW04\n" +
            "WvURB8uIkbnjE2Qhu+z4U1Hd7Sj1mXGiFR/SfVm5beANiS96WBLAEKhmwoziFKpL\n" +
            "c9MtVoJO9AnlxNbuWaybRSeg+C06/N7RbgsfMXw0V7YfDTI=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.SupplementDnsNames = true;

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);


        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(
                    result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals("MAaHBMCoAAE="));
    }

    [Fact]
    public void Does_supplement_IPv6()
    {
        // 3072 Bit RSA Key
        // CN=::1
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEZzCCAs8CAQAwDjEMMAoGA1UEAxMDOjoxMIIBojANBgkqhkiG9w0BAQEFAAOC\n" +
            "AY8AMIIBigKCAYEAyN+AOquFRroKBO43/SxuxWnsY91ZiHIU7rgBcK1/ZyjGcAVF\n" +
            "SbO0jCBoYLJCLvI9Dw3EbOzuvUbiMwdedmlXzOImL+rSYrJjl7V8sL/Hp5iCHs9J\n" +
            "iYeIYDFC6HwE7yonUWp4+lgjk0wZTaTalmhSIRujmggOPaMwTxNOxGYqQg6X2Dvp\n" +
            "Hxy0dzZY9RdCzDrf5wfDChKCX8j5A9wMVHzqBYfw5RK/XMNZ0kzl5ZV7rmggssfT\n" +
            "OWwmKQgo3+Nfs+nwclFGbip/w7PxLzaFI9E5oEHI/JxIBmlp3hkH+T2S6hS55R6e\n" +
            "jSXse8zhJtjQmNp/MqvHN2cVYIIy6q2AXIJ/wBqXtkxs6e/nVVF0VbWcV+wcHVhy\n" +
            "CAi+dOe1mKXwJtNf5I82/MPEL+EItPM0+VJT4PHkNc2dLr5d7rfm9K4p2DAg9427\n" +
            "Zq1R1t7w8WK/pBWe5RSo5WHY6hAjW/qTU7uRlZ0H2oLNBl3osNUp1df3ZoGXjJPX\n" +
            "f4QC4HjA/SLUPJwBAgMBAAGgggESMBwGCisGAQQBgjcNAgMxDhYMMTAuMC4xODM2\n" +
            "My4yMD4GCSqGSIb3DQEJDjExMC8wDgYDVR0PAQH/BAQDAgeAMB0GA1UdDgQWBBR7\n" +
            "txq8vqA31iRiNlazQpzMGEwAvzBKBgkrBgEEAYI3FRQxPTA7AgEFDBpDTElFTlQy\n" +
            "LmludHJhLmFkY3NsYWJvci5kZQwKSU5UUkFccnVkaQwOcG93ZXJzaGVsbC5leGUw\n" +
            "ZgYKKwYBBAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBm\n" +
            "AHQAdwBhAHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBk\n" +
            "AGUAcgMBADANBgkqhkiG9w0BAQsFAAOCAYEAOR68MvcdJiIc+1Reg2WAdVmJ9Wob\n" +
            "irvf+aaO2hH77MBIcKsLxTamssw05nh1pJrUWFbKCkSuVLc3mWWc4hzPl5F6eY+z\n" +
            "h/foKZaA1NX5Vy32Z2Tcda7UDXsZ6UqOdR+muHjoslGp68fnMw9M4yO2UZe4+cMf\n" +
            "O+7shLg1QFR7V2S0xRVVITrWKWmjl1n++wb0hrS3MmTbzyukUT1UYDwOXL71EVkA\n" +
            "RloUBVfuRjmyHAtqfi2Nk4d9TFluXT2LpLGZjCxQ+sqmADqZ9eYBs4ph8Q3TqDyd\n" +
            "YRHix2+fbiwvwEyVteLSfh3S5ccQcq0NQ3OKNSifczhWYWYifa4AIN5Z7DLuKBEp\n" +
            "3hXkd+KF58r0QE0tceCVPGTlGqRVB+in8MugQSg5Z6YIKGHyKYtWpq2KDVfxWH8x\n" +
            "02x5hAUlaR8uBPkx8ewieiWbgy9PyucKXvEL66RjS/N9Xff8PpJhR7IVwyPvq5a3\n" +
            "qTRja1q0Ayu2vrAFbkw7m18wL3MqnXQh/FXM\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.SupplementDnsNames = true;

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);


        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(
                    result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals("MBKHEAAAAAAAAAAAAAAAAAAAAAE="));
    }

    [Fact]
    public void Does_supplement_mixed_types()
    {
        // 3072 Bit RSA Key
        // CN=www.adcslabor.de,CN=192.168.0.1,CN=::1,C=DE
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEpTCCAw0CAQAwTDELMAkGA1UEBhMCREUxDDAKBgNVBAMTAzo6MTEUMBIGA1UE\n" +
            "AxMLMTkyLjE2OC4wLjExGTAXBgNVBAMTEHd3dy5hZGNzbGFib3IuZGUwggGiMA0G\n" +
            "CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDDgqwhvHWSzSJThX+KAahPUtIX0xK3\n" +
            "SBIACzsXADqzT10a5L5BJGv65Z8RUIkru431VlS7yEOVB5vowH+OuDXoJ9EBaC4q\n" +
            "F+Qaf6meoMy2YVonhKU8lOJsJ71LOVc67WKFAJQBIlzinA7mMabWJdLJvnpGTD7H\n" +
            "426dnWH9ExVXefXAX6itPvdfWVByK4kdFe6am0c6uVMWEr0b6rZ48xZh+FYq5j1m\n" +
            "e0Q9lVdHRyHmaQwHzNnZfkILTi/pJlcyxY/ghiSNazQEH2nd6LUsBdCZfX5yXe8h\n" +
            "EX1cSWQtUXXVAEfqLRyd/o9cHJZppPQbzIkGSW37Q1cGVpk+7u3so5+mI17PU+Vm\n" +
            "isV3GQvODp/Ki8Otvp0NM4SfGNFpAckJC06bzBjoSzZy77zoQuEliRzHACk/K34G\n" +
            "8b/dg+vV/r5J8B4zMYGnDpmMUqoMNS8/UZ+zSjIXkj22EFYY10EWu80TzzUW2uME\n" +
            "NAewJEARvmd1bFlvzHrd7XZBMQFqFoUUEYECAwEAAaCCARIwHAYKKwYBBAGCNw0C\n" +
            "AzEOFgwxMC4wLjE4MzYzLjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMC\n" +
            "B4AwHQYDVR0OBBYEFOjLxVNrCIJqiB9A7dwTi9BUtH2WMEoGCSsGAQQBgjcVFDE9\n" +
            "MDsCAQUMGkNMSUVOVDIuaW50cmEuYWRjc2xhYm9yLmRlDApJTlRSQVxydWRpDA5w\n" +
            "b3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBz\n" +
            "AG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBl\n" +
            "ACAAUAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBgQCQy3LSK4AC\n" +
            "bPDi1bL5HLRq/0U6DxXGhWPL3P7e/EdGgU86bg0upJ5a83B2MQyQ/vGlN+p1/ao8\n" +
            "Rdk9tDif1C69Ufia4glWzNiZHej5Wdn+1fadbFj32vcty+EMWFROhVY8ZSTCdyZv\n" +
            "fvJ7HzMQfVhbEW74D2S55lhhPJl3ZI7r+e77KNSsLikfv9SdyF75U3WqabqASa16\n" +
            "pDQ/FG7wv4I4CvcgbnRRWQ4W9eIlOyXP7jbQhSsMIzeuG273yfeQDUKqlVHxgA1K\n" +
            "m9nrsXKLYoJ77F07K938RAIJvftizFFsx4OKOemYhiKlMYRzUcZv/lZhTv9LdsCh\n" +
            "T0gY5NSgKnsy13dv2zFngm3TdNel+Erm4yDDtHvRgi/fH5nKYt9PU99m8vNpu9vQ\n" +
            "nWGbFpc3V/s5dKl3eItFLYyDHE45bIAmPuZH3jZ5XgQio4uBgAKe32oxdmm5XsLa\n" +
            "tLy3pn0hcDZHJnraibioAJGxA5pb87uZWNyv6hPC1ofmvd9YGAUovEY=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.SupplementDnsNames = true;

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);


        PrintResult(result);

        Assert.True(
            result.CertificateExtensions.ContainsKey(WinCrypt.szOID_SUBJECT_ALT_NAME2) &&
            Convert.ToBase64String(
                    result.CertificateExtensions[WinCrypt.szOID_SUBJECT_ALT_NAME2])
                .Equals("MCqHEAAAAAAAAAAAAAAAAAAAAAGHBMCoAAGCEHd3dy5hZGNzbGFib3IuZGU="));
    }

    [Fact]
    public void Does_not_supplement_anything_if_nothing_present()
    {
        // 2048 Bit RSA Key
        // CN=,C=DE
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEcTCCAtkCAQAwGDELMAkGA1UEBhMCREUxCTAHBgNVBAMTADCCAaIwDQYJKoZI\n" +
            "hvcNAQEBBQADggGPADCCAYoCggGBAMID8rc/c2v1bGVuzi2480adyXuT9ps8zWe2\n" +
            "dxUIt1BC6Qrp+Qog/dy9wJhuzz6e4QRKseWg8fubMKIWtKjvlOsG+OzG0cDhDsP9\n" +
            "r0Kvd2YCXw2kqWFBe1Y885bNX1B13R/vK3/LO4CNOUlAKrlvJPbGStQIQF8dZ2wB\n" +
            "IYhamPK5hic1zOk2PTw9QLLl9Bfmh53A6Beguj+C3WdQl1TDO24kg68D4ZhDiNE6\n" +
            "votstfNZWYZ/MvOUeHB1f2TNz1QxEvPTpOif2DXxLEvW7yrLd/dGUq+owh91qI04\n" +
            "Sv5IP3XVCFm4yRPy5Dn7U0DSv2QNOxbLX5vUwpKLcE38MKvgK4MPxG1TU2gtEwqA\n" +
            "p8YrJUNPGoKx8rsv7tI41Xa9uPZAmdm3UpsssxSh3ZwBQs2NY0DobFODPT4QPBL+\n" +
            "Kdg122GlOMSnPahpfqLy10vnKKRr0U5E8raMOB6aGpAzlNTQe53ZlW2EanolzMOB\n" +
            "ZVgFhyGvWJd1axinuaBAAVs1lMlGSQIDAQABoIIBEjAcBgorBgEEAYI3DQIDMQ4W\n" +
            "DDEwLjAuMTgzNjMuMjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAd\n" +
            "BgNVHQ4EFgQUWIHnwcy8A89ImgQIKvPQbTCIXwswSgYJKwYBBAGCNxUUMT0wOwIB\n" +
            "BQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFib3IuZGUMCklOVFJBXHJ1ZGkMDnBvd2Vy\n" +
            "c2hlbGwuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBm\n" +
            "AHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQ\n" +
            "AHIAbwB2AGkAZABlAHIDAQAwDQYJKoZIhvcNAQELBQADggGBAA8H7M16sY8/8feg\n" +
            "IU2GEmb+FzZlxkUp12kCS5j89JBgvEseU8vCnBChMjji2/wq3Ibc6SXaRFFs+SdR\n" +
            "hbde9MlzdnDp8mOToRkYj95WFNPxpZqi4QqUgpJy3s7bewLzXz3r4JS01qWEzE4a\n" +
            "8Aeqxd38Gwp2SSd2SVtp8SwpdfswEZke5Y9Cy1GiA4yK4rEZ4i5nhq3BuyQLhcOh\n" +
            "0iJod1Q4grQ9cTePETOMi9Llv+SI3iIOLtu6qQaWLerEQf1aGE4e5HQlgFckrFz9\n" +
            "yuIWtmfOnU4S53mkkwLG89E0Bu5r0wb+Q4Ytv3fm1LTYxc+Ezdb3hqklFfFmFumY\n" +
            "QFkXmP2HoXo7Exrm2LzkJrGbh9Aa+Ic9O9B5j7OAjRBNmGSM05guU7ssgqGu2OcC\n" +
            "JDMTSVRtnIF2SNJ3MflnTzv8fwPFQEkCPIikgKy4HEG7KkmelOOR9DVrgot0WXHD\n" +
            "xkuECyANnFYngtst+/c9pxSkHICCzmFYqrg9RK6GI57INCr2nQ==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.SupplementDnsNames = true;

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);


        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_empty_commonName()
    {
        // 2048 Bit RSA Key
        // CN=
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDXDCCAkQCAQAwCzEJMAcGA1UEAxMAMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
            "MIIBCgKCAQEA6c+ekUJOIzXi+pUk1yJlPQ3YAvJ4Pd+XC2XO6N+djh6NZBo6Vfch\n" +
            "YlSwZBVOuvIBWAo1UGS4WHhcPhyc1V5mTV+xIBdE2FAGU7/tmP8OorSwrK0uWnlm\n" +
            "xh4bqM7oNNTp1hqClrsu8HlA0JexjY8nCFm1o3ZVlc1UkOtHgddBqOeBmoLP6t58\n" +
            "6/qpp7/0xKn8Gyy0llarSEjzb4Q1WF/yTcQWQs0FGnTosiOeZjFwPtJy5a3QNm0N\n" +
            "ca3yxi98bRCDpVLrzw/vmoQfN6J+X4+jH/puu7T41Vpcn3KRO7hg1Joj3VzmFM6K\n" +
            "xXj2Fn4oMTOsVf30gUxWFPjRdHOWyn5ysQIDAQABoIIBCjAcBgorBgEEAYI3DQID\n" +
            "MQ4WDDEwLjAuMTkwNDMuMjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIH\n" +
            "gDAdBgNVHQ4EFgQUC2bPM5AoVdXCppGhooPAw12j8NAwQgYJKwYBBAGCNxUUMTUw\n" +
            "MwIBBQwKQldQLTIzMkM0NAwSQktVXFV3ZUdyYWRlbmVnZ2VyDA5wb3dlcnNoZWxs\n" +
            "LmV4ZTBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAA\n" +
            "UwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8A\n" +
            "dgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBAQA7dExmjDRsIAs6O6JwDkXP\n" +
            "ZAdv5qNyEO1TjQ8EDUl3hWhrjo2LdiX29/Apd7MvHf+OmTWNfvOHMy1R7uByhkSb\n" +
            "TINgpbHkT8zq9DY8rhV0Hk1CqEGqx9VZ6fJ8fElKXhmq4UYc2DwWgppmnofwnC5n\n" +
            "HAMpHLzOlcL49XYG3l/yBVrRKFhPJ+7wXrsxF0Kt8TFbQyQvzlBrn9J3He/toTnR\n" +
            "Gi5zMH4MtdDvb8lf64R9BVd/r9EQEKXOsDG2XG3X9oHpSrb9yQ4bnaimOW+qhzgS\n" +
            "Qbc+EMH4FY4v2YSfjsI3Lwqc5D/VUjjiurH09jtUokXLJme98UiwpFbBu2JDi2T/\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_no_subject_DN()
    {
        // 2048 Bit RSA Key
        // Subject DN is empty
        const string request =
            "-----BEGIN CERTIFICATE REQUEST-----\n" +
            "MIICRTCCAS0CAQAwADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN3I\n" +
            "pfU4s5WnSooZ5YXS/KM567BOo+kPIht61hgDYV1dKJw6monu3G9CZEbmKZROGaD6\n" +
            "Wgwrq0G0Tdumi4JDuV0N/mo1E+YYGHV0mJn3a6LRoOtpGtnXfXyfJTrvUqS8ojIr\n" +
            "VbKnF3DYVZUbzMbUXeNYvvhdZqbv+F777GAaRLPeMxQfwrx/jHq/sBobNZsMP55W\n" +
            "1BBbdXnDuFZ3vOKYuP0TnJnTt0AQvcAKod+BSZhhJ+LacXwuClGBv/hXE61ec/NE\n" +
            "UfkBfjhYMRnklVxNYVfKPRVOZHQeMICwN/LzYdXd2z8E/Y1buFOt9fppVft4rxK/\n" +
            "tvdcyasTSbyMMNqW8Y8CAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IBAQBwWbeu6pcv\n" +
            "1ma3WcxuZRjhAXLZFYO5S8MTAA5DuMAVQiWYCkViSdzwijTzy0ngb+tk/Jq4bIcu\n" +
            "Kv6dyTVBkshjOkhdFNqov98iruK4VDf6SLy55mlSpppBXXSq2iGmkurbTRPSc6vg\n" +
            "FqsZo1Yk9fevYBTv68oy5r9JXpQv6mwZFCWWkpG+5/2sJ7g0Z2Tlus08yB6gMYej\n" +
            "mNFV86EtLaT8MUNLYWdNeTSIUo5ywnnKPQNRCJFOGxxDrtaEk6THyhfq6JdeMrX3\n" +
            "kTnibd+tk1uev4YvxMh1Vh3E/H08REe+oXSIS380agnNR8bbPm9uXXoRFoBSzWdA\n" +
            "UuB3ABtxKzki\n" +
            "-----END CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_countryName_invalid()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de,C=UK,O=ADCS Labor,L=Munich
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDoDCCAogCAQAwUzEPMA0GA1UEBxMGTXVuaWNoMRMwEQYDVQQKEwpBRENTIExh\n" +
            "Ym9yMQswCQYDVQQGEwJVSzEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRl\n" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0YUGDn2SUYfGtCvbw7o5\n" +
            "jNzyAAafFxggO56A8xDgjoVqFm/6/L3gC6LWYonCm+7Od3LucQQ/T5pN3n7YQuoM\n" +
            "5DMq0H0W28mYiLPV1M8bOWjK1yVjCpsnShRSQLSThzG+oJS2GNmLVAIT4MvGLB8j\n" +
            "lYhoxVoTEFJe9DIokx+ND8B+rzY61oiczI84JMd0wmRUh7vmxiLDH105DPbk9JQu\n" +
            "vBi65T55UK/8FiyfI+n/f9vIUzRg7A3y3MmuIvRsLwQqCGebPcQynJb4ctvyEusy\n" +
            "qcr7RjNMEvXU2jTyg3OQ95YKKFDm1e8KWuXAQovbVsCQzZSyGrbreMjY3W5JjDZ2\n" +
            "dQIDAQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkqhkiG\n" +
            "9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU5jHx96HaHlJuMfEr\n" +
            "wIRY/JzsDWgwPgYJKwYBBAGCNxUUMTEwLwIBBQwKb3R0aS1vdHRlbAwOT1RUSS1P\n" +
            "VFRFTFx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcNAgIxWDBWAgEAHk4A\n" +
            "TQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUAIABLAGUAeQAgAFMA\n" +
            "dABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJKoZIhvcNAQELBQAD\n" +
            "ggEBAHF9KEclG5CQX+okcw0AcjTAeYHNMp6RLDdwyLOqShWubNzVeOl31ABYoASD\n" +
            "/9qpFR7qsodCjDOZLIiE6BEIxbPOGMTrZ0FbgHnexkyreGpfAm0f7jJzm+6iA/os\n" +
            "iHFA48DS5CMZd1LKvm3IP0bvGTVoYS0bRWWBSP67eiL9irpzApMgvCfRTJj6qqzp\n" +
            "htlXTjgOxTYT7DC1y4oXnfUoQypdASDNiUBVBcEPC6wOWWCLwzdJdk/kSenYeJl0\n" +
            "soDwHamNh0o+tmOdX2Wuyxh35vSMUaLztjNDU0kjXadEJFogdvfzv7X5+/w/KQlx\n" +
            "iddTemRyEEPZ3Xk6Apfthttqzwc=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_givenName_not_defined()
    {
        // 2048 Bit RSA Key
        // "CN=intranet.adcslabor.de,G=Test"
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDfDCCAmQCAQAwLzENMAsGA1UEKhMEVGVzdDEeMBwGA1UEAxMVaW50cmFuZXQu\n" +
            "YWRjc2xhYm9yLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt8F0\n" +
            "S+emD/3rWYUF7OSTx9httguDLf7IQd1uvVfsBdIk1kyf/MEmfPHHOs/Is8bLsz6y\n" +
            "yWtraHjv1QqUMy9nOlIdwP/MJV+rc2MAcWoupB4xUgfoS1Rixmc9VRKUDzLw1PWn\n" +
            "S14QzUu8Zd+oR370doMhGZlL4R59aXp/jBa/cxX2DGAZgBkQQzYejgEbWSh44Cs/\n" +
            "gVIqjKCJgra6zAXXoq2OT0uW0HjWCADHvl3yvN04wbakvNDhipUSAGBrGivHlCm1\n" +
            "xpVXNBpjo3Lfl6r9peXKufwwAAo6WaQURClD5Uy1fmuAH75YVZedwTyfpDQdlnAR\n" +
            "rUuSzr/T7uHcirgIuQIDAQABoIIBBjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkw\n" +
            "NDQuMjA+BgkqhkiG9w0BCQ4xMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQU\n" +
            "LzwfyiOg/meb9cnbM6hUMh0zA+wwPgYJKwYBBAGCNxUUMTEwLwIBBQwKb3R0aS1v\n" +
            "dHRlbAwOT1RUSS1PVFRFTFx1d2UMDnBvd2Vyc2hlbGwuZXhlMGYGCisGAQQBgjcN\n" +
            "AgIxWDBWAgEAHk4ATQBpAGMAcgBvAHMAbwBmAHQAIABTAG8AZgB0AHcAYQByAGUA\n" +
            "IABLAGUAeQAgAFMAdABvAHIAYQBnAGUAIABQAHIAbwB2AGkAZABlAHIDAQAwDQYJ\n" +
            "KoZIhvcNAQELBQADggEBAJir0lIk5w2uESofvvYDp9QOj0/aEHL2bVLup7s2al0o\n" +
            "TNy/UJ/YQTckPXRr4J2kVUxH9HLo97V5qYOQ1J082MIckjJjdYRsSVh6VTJ5njTY\n" +
            "4p5olpbegQyfJzFPz3L2ktk1fetuFck0NtM9cMVMpVnXrA17/LS7Rvn5aXnRKYNK\n" +
            "KP3NjtTf9g+a/CVJ0NYo9R5XL4kf/vIQkl7PYRy/FAi2ASrDb1woLUOBh4rBFH+s\n" +
            "PRIbFsXr7BdWMDKM92zH8bUCrPvNuN+hjdLrgREdONYf52UdZRt/nwShKkMHVxDW\n" +
            "f482T7HTzF4MuKb/m+x7nUz1eMFHXTy7TFoaYRxv3V0=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Allow_process_name_valid()
    {
        var policy = _policy;
        policy.AllowedProcesses.Add("powershell.exe");

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Allow_process_name_not_forbidden()
    {
        var policy = _policy;
        policy.DisallowedProcesses.Add("certreq.exe");

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Allow_process_name_invalid_in_audit_mode()
    {
        var policy = _policy;
        policy.AuditOnly = true;
        policy.AllowedProcesses.Add("taskhostw.exe");

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Deny_process_name_invalid()
    {
        var policy = _policy;
        policy.AllowedProcesses.Add("taskhostw.exe");

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Deny_process_name_unknown()
    {
        // 2048 Bit RSA Key
        // CN=somewebsite.intra.adcslabor.de
        // no process information
        const string request =
            "-----BEGIN CERTIFICATE REQUEST-----" +
            "MIIC8zCCAdsCAQAwKTEnMCUGA1UEAwwec29tZXdlYnNpdGUuaW50cmEuYWRjc2xh" +
            "Ym9yLmRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3cil9TizladK" +
            "ihnlhdL8oznrsE6j6Q8iG3rWGANhXV0onDqaie7cb0JkRuYplE4ZoPpaDCurQbRN" +
            "26aLgkO5XQ3+ajUT5hgYdXSYmfdrotGg62ka2dd9fJ8lOu9SpLyiMitVsqcXcNhV" +
            "lRvMxtRd41i++F1mpu/4XvvsYBpEs94zFB/CvH+Mer+wGhs1mww/nlbUEFt1ecO4" +
            "Vne84pi4/ROcmdO3QBC9wAqh34FJmGEn4tpxfC4KUYG/+FcTrV5z80RR+QF+OFgx" +
            "GeSVXE1hV8o9FU5kdB4wgLA38vNh1d3bPwT9jVu4U631+mlV+3ivEr+291zJqxNJ" +
            "vIww2pbxjwIDAQABoIGEMIGBBgkqhkiG9w0BCQ4xdDByMA4GA1UdDwEB/wQEAwIH" +
            "gDATBgNVHSUEDDAKBggrBgEFBQcDATAdBgNVHQ4EFgQUEskQwgjBJxMXqii7Ox3F" +
            "TfTQHF0wLAYDVR0RAQH/BCIwIIIec29tZXdlYnNpdGUuaW50cmEuYWRjc2xhYm9y" +
            "LmRlMA0GCSqGSIb3DQEBBQUAA4IBAQDIQrqmM0q8jnquRWV136E+tQxF6VFcBu3R" +
            "AraAkyZ+Aw8NVrRXzyBCL+hupW9zPF9B6xHNfyCbxX5Kqf2Ur5+FuemmzYkBAsHw" +
            "L2jbj0KymYwv+31AMubLZHO3oyq/GuJkP6VnBm7JpI5kSncU9zA2Sq/lgiUk+wg+" +
            "FGHD3m/c8eUDUJCWM79W2buAgG0EAU/a96gPvcHUq2d5eFduLYOzLb5BA20g7hit" +
            "fYRvkB/pz1QtanK+I4vEEb/wMj6Dj6Tyo4JsSqts5bSS1uFkPsKtzmA4bdqxml2f" +
            "s4Exo9Lmx0bAKHD3xMUX19RukXDpM6ssBGe71LGqaAAfNH40WHBO" +
            "-----END CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.AllowedProcesses.Add("taskhostw.exe");

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Deny_process_name_forbidden()
    {
        var policy = _policy;
        policy.DisallowedProcesses.Add("powershell.exe");

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Allow_crypto_provider_valid()
    {
        var policy = _policy;
        policy.AllowedCryptoProviders.Add("Microsoft Software Key Storage Provider");

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string> { { "RequestCSPProvider", "Microsoft Software Key Storage Provider" } });

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Allow_crypto_provider_not_forbidden()
    {
        var policy = _policy;
        policy.DisallowedCryptoProviders.Add("Microsoft Enhanced RSA and AES Cryptographic Provider");

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string> { { "RequestCSPProvider", "Microsoft Software Key Storage Provider" } });

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.ERROR_SUCCESS));
    }

    [Fact]
    public void Deny_crypto_provider_invalid()
    {
        var policy = _policy;
        policy.AllowedCryptoProviders.Add("Microsoft Platform Crypto Provider");

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string> { { "RequestCSPProvider", "Microsoft Software Key Storage Provider" } });

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Deny_crypto_provider_unknown()
    {
        var policy = _policy;
        policy.AllowedCryptoProviders.Add("Microsoft Platform Crypto Provider");

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);


        result = _validator.VerifyRequest(result, policy, dbRow, _template);
        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Deny_crypto_provider_forbidden()
    {
        var policy = _policy;
        policy.DisallowedCryptoProviders.Add("Microsoft Software Key Storage Provider");

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10,
            new Dictionary<string, string> { { "RequestCSPProvider", "Microsoft Software Key Storage Provider" } });

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Deny_commonName_too_long()
    {
        var policy = _policy;

        policy.Subject.Clear();

        policy.Subject.Add(
            new SubjectRule
            {
                Field = RdnTypes.CommonName,
                Mandatory = true,
                MaxLength = 4,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"^[-_a-zA-Z0-9]*\.adcslabor\.de$" }
                }
            }
        );

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_policy_pattern_expression_invalid_Cidr()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // ipAddress=192.168.0.1
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDgTCCAmkCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAssXMb23gWNQPuO2OtHubWSIH\n" +
            "f05rvRfHr4pRmMoI3JFuwnTHs5ho3sLtLu/NOroH5xUAthC/OJoUFOusu/9vlptf\n" +
            "8oPABXvHRCuCsEhdfGB/+p7Wf/FMm+YU9KhwNUM1kt1wQ2XAFKEi11iaF8YkzyQ1\n" +
            "PP8zqRU0UNEXlF1GWgc1DOnOkKKkZS2jE1LQ6yBm+suD++EMGPUH+7OSNDGvtWEM\n" +
            "D9LMhH+vcdYpABJbz7jzjytIXmayEQM4oz8CT/2NfRMzSeMOheDCILJugK43A+qe\n" +
            "BpTfie0LA99vYFIHe4vh7Mxc+FR+aHL3dP3doQnt98a0R14XnNn/uUadA46C2QID\n" +
            "AQABoIIBGjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
            "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
            "bC5leGUwUgYJKoZIhvcNAQkOMUUwQzAOBgNVHQ8BAf8EBAMCB4AwEgYDVR0RAQH/\n" +
            "BAgwBocEwKgAATAdBgNVHQ4EFgQUhkzXt+AAu7HigUpHv45MuccLo/IwZgYKKwYB\n" +
            "BAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBh\n" +
            "AHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMB\n" +
            "ADANBgkqhkiG9w0BAQsFAAOCAQEAb0k413f2rAuTtb3cmS3e0w2jLR71d8+OZZ4w\n" +
            "HN618i5xc/1boSY7p/M5rWRbZp4xdtpwYtUFOsUxuOrZdTjYckY6i834r9xZ9BCP\n" +
            "cw3V0FISgyZ1g5lIkV1rQW2V66ZA3SVyzXoPQQ0AJBMdiudIbFsg1BJ3LwmIjuGS\n" +
            "4TF3unbiVDFNXchtwICznn2OFPWPeGnz37xRiuWK7rheXOU+KHWHaVUpyar8J+5O\n" +
            "RRsjitR+Lgqvm/KYUacA5TARMVhGjPzS4O42VYCGjlMR74YaQi+LH3Vezft5G/Ft\n" +
            "CpV76XuDMJqMk4VrPkh1rLljbGqKzuQzIuCVAPFBhsLCqnHByQ==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;

        policy.SubjectAlternativeName.Clear();

        policy.SubjectAlternativeName.Add(
            new SubjectRule
            {
                Field = SanTypes.IpAddress,
                MaxOccurrences = 10,
                MaxLength = 64,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"thisIsNotACidrMask", TreatAs = PatternType.CIDR }
                }
            }
        );

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_policy_pattern_expression_invalid_RegEx()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // dnsName=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDkjCCAnoCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA3GmfcSDSunQ6+vmz9mTHcEKg\n" +
            "DMzDSXj0lQ7Erazl9CJ4WzROZaa1BUITfRlVXreku6ljYsO3jyTDBRBtCUXNwFk+\n" +
            "MTmzTqXx82MRpK2ATDp2jEPfP7l7K30DwDyiapkpaAvZlxIVWtIDoGxAG+yRFjAF\n" +
            "Qh4HDvSaBoaNvwdjZsUcdgOuJQbIwBhto/RB+4L23oT7+8e2GyRMm/bQK2gDvCbV\n" +
            "9SwTwm9gXljth0wuZ8RRkC7MMVIiPaxUH575SUKE7YvHeZ4Hq20Q2XYBSigqNXBM\n" +
            "VCUVCfsBGA18/MR/ZMFSSCIt2KLjkpp5q9gOCibw0oPrGTqUoLtCkLREbMrHbQID\n" +
            "AQABoIIBKzAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
            "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
            "bC5leGUwYwYJKoZIhvcNAQkOMVYwVDAOBgNVHQ8BAf8EBAMCB4AwIwYDVR0RAQH/\n" +
            "BBkwF4IVaW50cmFuZXQuYWRjc2xhYm9yLmRlMB0GA1UdDgQWBBRmh46ij+b3RODb\n" +
            "JXIj5NFC58DFZzBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
            "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
            "UAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBAQAmQ8B9fZ+ewB3+\n" +
            "kDFsJcqeMJ+nbFBcHJKmKfhn9564tiBZayK8kpkTvS1Cjb5C79Yimimw2AqGqdFK\n" +
            "W3+wWPCkFN996GoXFOU+lg3I5Byz3Eq4Vyv/H7RCufC68ezVG5v4EaqE4TsYcfoE\n" +
            "zH8HJu0jKKf+QKj9LpXI+HYLwvQ0Fyz4lr839NMidsPF4AWMpEXs/2OSTjg5qDVj\n" +
            "LKMPzd0wrOea0XWx2fEeibdW+KFi1656J+OIGuYP/q0SaPqYgFey+kOS2KLz+9/r\n" +
            "CA+TvKzFxxgRPAfA0TO7GAuwspV2wLOfXVOxIpG5GkmpxeK0nZvyw9HvxWWNlkgw\n" +
            "kbUQqV43\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;

        policy.SubjectAlternativeName.Clear();

        policy.SubjectAlternativeName.Add(
            new SubjectRule
            {
                Field = SanTypes.DnsName,
                MaxOccurrences = 10,
                MaxLength = 64,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"thisIsNotARegEx" }
                }
            }
        );

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_policy_pattern_empty()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // ipAddress=192.168.0.1
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIDgTCCAmkCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB\n" +
            "IjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAssXMb23gWNQPuO2OtHubWSIH\n" +
            "f05rvRfHr4pRmMoI3JFuwnTHs5ho3sLtLu/NOroH5xUAthC/OJoUFOusu/9vlptf\n" +
            "8oPABXvHRCuCsEhdfGB/+p7Wf/FMm+YU9KhwNUM1kt1wQ2XAFKEi11iaF8YkzyQ1\n" +
            "PP8zqRU0UNEXlF1GWgc1DOnOkKKkZS2jE1LQ6yBm+suD++EMGPUH+7OSNDGvtWEM\n" +
            "D9LMhH+vcdYpABJbz7jzjytIXmayEQM4oz8CT/2NfRMzSeMOheDCILJugK43A+qe\n" +
            "BpTfie0LA99vYFIHe4vh7Mxc+FR+aHL3dP3doQnt98a0R14XnNn/uUadA46C2QID\n" +
            "AQABoIIBGjAcBgorBgEEAYI3DQIDMQ4WDDEwLjAuMTkwNDQuMjA+BgkrBgEEAYI3\n" +
            "FRQxMTAvAgEFDApvdHRpLW90dGVsDA5PVFRJLU9UVEVMXHV3ZQwOcG93ZXJzaGVs\n" +
            "bC5leGUwUgYJKoZIhvcNAQkOMUUwQzAOBgNVHQ8BAf8EBAMCB4AwEgYDVR0RAQH/\n" +
            "BAgwBocEwKgAATAdBgNVHQ4EFgQUhkzXt+AAu7HigUpHv45MuccLo/IwZgYKKwYB\n" +
            "BAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBh\n" +
            "AHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMB\n" +
            "ADANBgkqhkiG9w0BAQsFAAOCAQEAb0k413f2rAuTtb3cmS3e0w2jLR71d8+OZZ4w\n" +
            "HN618i5xc/1boSY7p/M5rWRbZp4xdtpwYtUFOsUxuOrZdTjYckY6i834r9xZ9BCP\n" +
            "cw3V0FISgyZ1g5lIkV1rQW2V66ZA3SVyzXoPQQ0AJBMdiudIbFsg1BJ3LwmIjuGS\n" +
            "4TF3unbiVDFNXchtwICznn2OFPWPeGnz37xRiuWK7rheXOU+KHWHaVUpyar8J+5O\n" +
            "RRsjitR+Lgqvm/KYUacA5TARMVhGjPzS4O42VYCGjlMR74YaQi+LH3Vezft5G/Ft\n" +
            "CpV76XuDMJqMk4VrPkh1rLljbGqKzuQzIuCVAPFBhsLCqnHByQ==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;

        policy.SubjectAlternativeName.Clear();

        policy.SubjectAlternativeName.Add(
            new SubjectRule
            {
                Field = SanTypes.IpAddress,
                MaxOccurrences = 10,
                MaxLength = 64,
                Patterns = new List<Pattern>()
            }
        );

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }

    [Fact]
    public void Deny_sid_extension_forbidden()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // sid=S-1-5-21-1381186052-4247692386-135928078-500
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----" +
            "MIIEvjCCAyYCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB" +
            "ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtpktqmDWCzarYusWvZ/O0/AC" +
            "i6hVnBR6tzUCeWcLA6qmznWSqdDym0yVndHRTCqYiZgvgfMBKRr9nTQPzLMM3k+5" +
            "BfuEFTgCCvlmlRxSLuDenI4w3CIGLDkRxv/pAZO2VeIdYAsfGm79QV5/tU6UZ3ZN" +
            "G4ix5bb7udfJOdBN576Q2qtte1BnMqzzwJB8fH8Jc/MOx75flx/e+2AmZbeIDtxD" +
            "j2MDG+kQ3t+PFfws8LSAy5q/CHUVlkoSb0BT0U/X1UBcQQriSVqofK9JDB1Ok5XU" +
            "QdsBKdZGyeChRUrS10iEgTWpawrfvt2MbObwhpHrV/WDdVmEif4t5PKWqgFahHZT" +
            "tWt1r4JGMxRLHfAGnjOt2k14JpOpqMAgkHPLGPXJsmlD4un8enrx5QU156CwAHLg" +
            "6ltkDi+sgkeWhMMok4fb21uzKouclacE2vR+l/F8LUP52AeBsQAmRucyJkXbM0QY" +
            "eR9w9Cu2RT93s+DFPTtE1U3093StXhLY5GzsG2rdAgMBAAGgggFXMBwGCisGAQQB" +
            "gjcNAgMxDhYMMTAuMC4xOTA0NC4yMD4GCSsGAQQBgjcVFDExMC8CAQUMCkxBUFRP" +
            "UC1VV0UMDkxBUFRPUC1VV0VcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3" +
            "DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBl" +
            "ACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMIGO" +
            "BgkqhkiG9w0BCQ4xgYAwfjAOBgNVHQ8BAf8EBAMCB4AwTQYJKwYBBAGCNxkCBEAw" +
            "PqA8BgorBgEEAYI3GQIBoC4ELFMtMS01LTIxLTEzODExODYwNTItNDI0NzY5MjM4" +
            "Ni0xMzU5MjgwNzgtNTAwMB0GA1UdDgQWBBRIW5wIKxgYQ54ZqtEnPJb1up2dHzAN" +
            "BgkqhkiG9w0BAQsFAAOCAYEAV9BiaDSo495k4WccuFVRoXpxfl46NuZA7WBL/7F5" +
            "smqmslc5pVnXWf6HLigoEJIKBmZ1ro4FvL73o9cX0sL4xx3b8DO0GSQ7DsB5fLy4" +
            "Rm3pynkpIblbwDLcHfZGCsY1ZOOuBLXpDyBhqWv37iDKcErtRR/guoLEWScUAfWr" +
            "LAAXuDkJF7pOAQNytUDGG+Gk6GILvGs1TiDYtFdM9K4A1uyjnhcU3fv3uLXC3mdZ" +
            "S1PA/8sO7ItSJyf/CgDsJZnZ2/WNdAq05po0ELjmte3o/n+8avAXqot8XjC+Jm1n" +
            "xieO9UfUwubES3b2S1GLpFdW20fsVsjhyI76nOPqDDRXhqksiIEMDi0S1QjQyUbR" +
            "smdERk7+lImY1iOfJH3ZrG+cpEEMDZCNpvxSn9rgq8CbIR4v0K6SG4PlX4bUIpV7" +
            "giA5RXlS0BWKeT4g+7p35hAqf/NFAJ3HP0tIkY7TBKOB4nhRUixaJPUFTvnZZCT6" +
            "FruEf1rk3/tB/ywnVKL9KRsn" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERTSRV_E_TEMPLATE_DENIED));
    }

    [Fact]
    public void Allow_remove_sid_extension()
    {
        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de
        // sid=S-1-5-21-1381186052-4247692386-135928078-500
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----" +
            "MIIEvjCCAyYCAQAwIDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMIIB" +
            "ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAtpktqmDWCzarYusWvZ/O0/AC" +
            "i6hVnBR6tzUCeWcLA6qmznWSqdDym0yVndHRTCqYiZgvgfMBKRr9nTQPzLMM3k+5" +
            "BfuEFTgCCvlmlRxSLuDenI4w3CIGLDkRxv/pAZO2VeIdYAsfGm79QV5/tU6UZ3ZN" +
            "G4ix5bb7udfJOdBN576Q2qtte1BnMqzzwJB8fH8Jc/MOx75flx/e+2AmZbeIDtxD" +
            "j2MDG+kQ3t+PFfws8LSAy5q/CHUVlkoSb0BT0U/X1UBcQQriSVqofK9JDB1Ok5XU" +
            "QdsBKdZGyeChRUrS10iEgTWpawrfvt2MbObwhpHrV/WDdVmEif4t5PKWqgFahHZT" +
            "tWt1r4JGMxRLHfAGnjOt2k14JpOpqMAgkHPLGPXJsmlD4un8enrx5QU156CwAHLg" +
            "6ltkDi+sgkeWhMMok4fb21uzKouclacE2vR+l/F8LUP52AeBsQAmRucyJkXbM0QY" +
            "eR9w9Cu2RT93s+DFPTtE1U3093StXhLY5GzsG2rdAgMBAAGgggFXMBwGCisGAQQB" +
            "gjcNAgMxDhYMMTAuMC4xOTA0NC4yMD4GCSsGAQQBgjcVFDExMC8CAQUMCkxBUFRP" +
            "UC1VV0UMDkxBUFRPUC1VV0VcdXdlDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3" +
            "DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBl" +
            "ACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMIGO" +
            "BgkqhkiG9w0BCQ4xgYAwfjAOBgNVHQ8BAf8EBAMCB4AwTQYJKwYBBAGCNxkCBEAw" +
            "PqA8BgorBgEEAYI3GQIBoC4ELFMtMS01LTIxLTEzODExODYwNTItNDI0NzY5MjM4" +
            "Ni0xMzU5MjgwNzgtNTAwMB0GA1UdDgQWBBRIW5wIKxgYQ54ZqtEnPJb1up2dHzAN" +
            "BgkqhkiG9w0BAQsFAAOCAYEAV9BiaDSo495k4WccuFVRoXpxfl46NuZA7WBL/7F5" +
            "smqmslc5pVnXWf6HLigoEJIKBmZ1ro4FvL73o9cX0sL4xx3b8DO0GSQ7DsB5fLy4" +
            "Rm3pynkpIblbwDLcHfZGCsY1ZOOuBLXpDyBhqWv37iDKcErtRR/guoLEWScUAfWr" +
            "LAAXuDkJF7pOAQNytUDGG+Gk6GILvGs1TiDYtFdM9K4A1uyjnhcU3fv3uLXC3mdZ" +
            "S1PA/8sO7ItSJyf/CgDsJZnZ2/WNdAq05po0ELjmte3o/n+8avAXqot8XjC+Jm1n" +
            "xieO9UfUwubES3b2S1GLpFdW20fsVsjhyI76nOPqDDRXhqksiIEMDi0S1QjQyUbR" +
            "smdERk7+lImY1iOfJH3ZrG+cpEEMDZCNpvxSn9rgq8CbIR4v0K6SG4PlX4bUIpV7" +
            "giA5RXlS0BWKeT4g+7p35hAqf/NFAJ3HP0tIkY7TBKOB4nhRUixaJPUFTvnZZCT6" +
            "FruEf1rk3/tB/ywnVKL9KRsn" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var policy = _policy;
        policy.SecurityIdentifierExtension = PolicyAction.REMOVE_FROM_ISSUED_CERTIFICATE;

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.Contains(WinCrypt.szOID_NTDS_CA_SECURITY_EXT, result.DisabledCertificateExtensions);
    }

    [Fact]
    public void Deny_all_known_RDN_types_identified()
    {
        // 3072 Bit RSA Key
        // CN=test,C=DE,E=test@test.com,DC=test,L=test,O=test,OU=test,S=test,G=test,I=test,SN=test,STREET=test,T=test,OID.1.2.840.113549.1.9.2=test,OID.1.2.840.113549.1.9.8=test,OID.2.5.4.5=test,POSTALCODE=12345,POBOX=test,PHONE=123,DESCRIPTION=test
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIFpzCCBA8CAQAwggFMMQ0wCwYDVQQNEwR0ZXN0MQwwCgYDVQQUEwMxMjMxDTAL\n" +
            "BgNVBBITBHRlc3QxDjAMBgNVBBETBTEyMzQ1MQ0wCwYDVQQFEwR0ZXN0MRMwEQYJ\n" +
            "KoZIhvcNAQkIEwR0ZXN0MRMwEQYJKoZIhvcNAQkCEwR0ZXN0MQ0wCwYDVQQMEwR0\n" +
            "ZXN0MQ0wCwYDVQQJEwR0ZXN0MQ0wCwYDVQQEEwR0ZXN0MQ0wCwYDVQQrEwR0ZXN0\n" +
            "MQ0wCwYDVQQqEwR0ZXN0MQ0wCwYDVQQIEwR0ZXN0MQ0wCwYDVQQLEwR0ZXN0MQ0w\n" +
            "CwYDVQQKEwR0ZXN0MQ0wCwYDVQQHEwR0ZXN0MRQwEgYKCZImiZPyLGQBGRYEdGVz\n" +
            "dDEcMBoGCSqGSIb3DQEJARYNdGVzdEB0ZXN0LmNvbTELMAkGA1UEBhMCREUxDTAL\n" +
            "BgNVBAMTBHRlc3QwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCznyT5\n" +
            "62aKa8JKqT3kujFMp3VP/Vp3cyXPbzKU9XORgC4e8zq1px0JQzvrPFbCxI+D1g+T\n" +
            "MFl81PNtcRv+sXB132UIE7WJTVQI9G7rFgrybnAAqqlX/ex3YRuGcf/Cbzr7T5XT\n" +
            "ZNQxHj1Ro3X2Uf+A7sHwby+/o3rZi+iWJ9ydpMOjIZVnRNF+9BBxRxHsTRyT13bM\n" +
            "9xT5D7PRu5cPcSryagKEyxlkCQInyTVcDPElk9Yh+u+lfZW8HMUfvwutLTWmBesb\n" +
            "BAl88u8MG6N/X3HPLdOTuymOF6D7N9gZDX/CSBCR6ivBfK24t2hsThM0pMelxbun\n" +
            "9R0bKJ8/giKylPsDGrhySMMa9qzwg7BtMf3U50a7ifIO0QuwqG1tqpVapZ34qHyO\n" +
            "BjmSC/gmRzXLnrBBfHZ1T2M0cTzFNUW2Z5DEZhE1I2Wi31c9W/TCgaVmTeiJPL6b\n" +
            "5uiMAhijf4waHgo+jUYmSvGCG+6TimOhGbR04C3ydBFXiCpvJKj+V+sFuX0CAwEA\n" +
            "AaCCARIwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE4MzYzLjIwPgYJKoZIhvcNAQkO\n" +
            "MTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFO1m2UMNDRr23DSRF2iJaa5O\n" +
            "cO9kMEoGCSsGAQQBgjcVFDE9MDsCAQUMGkNMSUVOVDIuaW50cmEuYWRjc2xhYm9y\n" +
            "LmRlDApJTlRSQVxydWRpDA5wb3dlcnNoZWxsLmV4ZTBmBgorBgEEAYI3DQICMVgw\n" +
            "VgIBAB5OAE0AaQBjAHIAbwBzAG8AZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBl\n" +
            "AHkAIABTAHQAbwByAGEAZwBlACAAUAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3\n" +
            "DQEBCwUAA4IBgQBug1vfhNh5hhBkumqHCpEVe11Ll0UWTn2FLKM5UgkerLEOKwvq\n" +
            "R0LtoNHCdJJ5Xfw90eErgMr31cdks8HVlUyW13zYTJ3HPSrq/nxq7RNl6cf/utJy\n" +
            "G2XXpq/C2JKRhls07YLyTZrlrTTvA9aZha8ODD9M0OAMpCu4JmSebxXibyxAwnEo\n" +
            "aWnR4RlovJDe3nYZCjQqsXIJ5gbcFQJ0Vz7ObGUt2yFqAcCjHHiVeF3B4CjrdxIw\n" +
            "BQ37J2ktvD2hLeQ0cDxkMfu8oy5Hah0RTNamPy03rNZlVBjDieTRRhOsWcRKSJ0H\n" +
            "/s37wIGLrMN+2dooXpN+ZO01M0synAPDKLZC8PSyacIJ9+tolj3axSQy1XTscspi\n" +
            "oX5VoFliBOLo32PN1+RU4qdxx331C3sPQTI/sNobq58tqh94rTHvzpa34RrkG5JN\n" +
            "TTFXhCzpku8oCQeCAwYgo5NE8Uqt6EIJat1tlC2RVznjX/5rB2Qh7jo1+DiXaOEU\n" +
            "4FGWrTPcqLQL+SQ=\n" +
            "-----END NEW CERTIFICATE REQUEST-----";


        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);
        var identities = dbRow.GetIdentities(true);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.CommonName));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.Country));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.Email));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.DomainComponent));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.Locality));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.Organization));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.OrgUnit));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.State));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.GivenName));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.Initials));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.SurName));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.StreetAddress));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.Title));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.UnstructuredName));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.UnstructuredAddress));
        Assert.Contains(identities, x => x.Key.Equals(RdnTypes.DeviceSerialNumber));
        Assert.Contains(identities, x => x.Key.Equals("postalCode"));
        Assert.Contains(identities, x => x.Key.Equals("postOfficeBox"));
        Assert.Contains(identities, x => x.Key.Equals("telephoneNumber"));
        Assert.Contains(identities, x => x.Key.Equals("description"));
    }

    [Fact]
    public void Deny_commonName_invalid_dnsName_invalid_PKCS7_encoded()
    {
        // CN=this-is-a-test
        // dnsName=this-is-a-test
        const string request =
            "-----BEGIN PKCS #7 SIGNED DATA-----\n" +
            "MIINmAYJKoZIhvcNAQcCoIINiTCCDYUCAQExDzANBglghkgBZQMEAgEFADCCBKcG\n" +
            "CSqGSIb3DQEHAaCCBJgEggSUMIIEkDCCAvgCAQAwGTEXMBUGA1UEAxMOdGhpcy1p\n" +
            "cy1hLXRlc3QwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQDrj8b+p7kZ\n" +
            "TBC9qNsTy/WUz15ZP9r2my4q0h3SqJHcWOMsw+rVn71hktdF0h7qJ01NpYj36h8P\n" +
            "/lJx+5n3ELqRmQmWuoT/pyv2JNpIr85DFHrOhyLnbeTmoPCffxbC13Htc5MsiNkw\n" +
            "zjJKccEIpThswSsv4Sb5rVpMTnI6hax00SbKOuvbLxgMlCk6XYFbLl17bjhs3S76\n" +
            "QHet6fzSjs6pweHpzvXVkSqT7SfBNcUjiKxE6kZdPq/i1H/UxpFmicl1QdKe41ng\n" +
            "CkHC++Exyd9Q6LpOItxwcyaGnjFjTEKhEcFafPESoiz4UhQe9cvezVA0GGkfMLIV\n" +
            "IHU8Oquo/CLfHypD7Zo3lidj7BLkNoJ2wjqYhyTN5bGMF8TjJwIuVCdSrxsy5PO/\n" +
            "1KhQlq8o15wZH87uq2RDmHwaPrUNnUvc+HDzBRK4zQRBgJkNgFMKmAzcg/lMZIjI\n" +
            "LubTYAUUxV+s1zayxX4AKUkOl0qwB408BlPR9AgonscyRgHZXoAC8BkCAwEAAaCC\n" +
            "ATAwHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjE4MzYzLjIwSgYJKwYBBAGCNxUUMT0w\n" +
            "OwIBBQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFib3IuZGUMCklOVFJBXHJ1ZGkMDnBv\n" +
            "d2Vyc2hlbGwuZXhlMFwGCSqGSIb3DQEJDjFPME0wDgYDVR0PAQH/BAQDAgeAMBwG\n" +
            "A1UdEQEB/wQSMBCCDnRoaXMtaXMtYS10ZXN0MB0GA1UdDgQWBBTGOY+4vRUIPXd/\n" +
            "VKw0lskOiBAsyDBmBgorBgEEAYI3DQICMVgwVgIBAB5OAE0AaQBjAHIAbwBzAG8A\n" +
            "ZgB0ACAAUwBvAGYAdAB3AGEAcgBlACAASwBlAHkAIABTAHQAbwByAGEAZwBlACAA\n" +
            "UAByAG8AdgBpAGQAZQByAwEAMA0GCSqGSIb3DQEBCwUAA4IBgQDEXpI2qKbCcQNk\n" +
            "xFQ7zWIbpIEn1ZPYp4Yh1665KOR0AUXNNgD5DeuwOOv6TBZYhk2GG3NQbghCZRSU\n" +
            "W7ErrHciv4fIZn9lrvSvl8yeRCaZWe5Iq9Y/n8Mi+o30c5MRkpk2TpaXAWz91vbX\n" +
            "WkC6NctcazsbTg4O09pgZFwY1/+sjcwliCUYNfX2eIjrBqSDEzWFHRwXp0Nl8qLu\n" +
            "HDybDu8PJqRalGwjmHnbt5grqGpu7PLnpkGut71Jq5n+MM5k62E5tzDSA+6HEAUd\n" +
            "CL/uKS/fayVp7ZSAo93lXlml1o7CbEz7g7pIfMel+Pnrk3T6hFR/zbq8m+tlar4m\n" +
            "uohOBvnr5I3lDAGC4Yit/JEiZJRvT73ESEQvTZvlDSWyNt0sOOJEzYsGA2ASoINO\n" +
            "3ynSVhJCzeiwhT2p0X+2ghKY8hPhL5aFa6fxjqb/aj5gEk69eIfql3pzC3Bb6vbS\n" +
            "Ym9bWkxH134NkATEaweix9oKAjc/mDhJgE7w7oe4wTkSWIqMFougggcHMIIHAzCC\n" +
            "BOugAwIBAgITcwAIDlrU+8kfM1yNGQACAAgOWjANBgkqhkiG9w0BAQsFADB0MQsw\n" +
            "CQYDVQQGEwJERTEQMA4GA1UECBMHQmF2YXJpYTEPMA0GA1UEBxMGTXVuaWNoMRMw\n" +
            "EQYDVQQKEwpBRENTIExhYm9yMQswCQYDVQQLEwJJVDEgMB4GA1UEAxMXQURDUyBM\n" +
            "YWJvciBJc3N1aW5nIENBIDEwHhcNMjIwNTI3MTE0NTA2WhcNMjMwNTI3MTE0NTA2\n" +
            "WjAPMQ0wCwYDVQQDEwRydWRpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n" +
            "AQEArAbgsEjyO5ntIYeXs03gYY7O36VwDTpXl/aZXnfYx/+0BnXc1jhR6ptj0T1J\n" +
            "BHsRk9jN1zjpmYqgPii2z09ngbcY8eiQMNvAgGurm/SW3JPzJyu9k0ymp8FL4AAQ\n" +
            "9WQL1uLDLfkq7AOna94Qw9m3Lj7NsqkH5Fz31Qv7C/ZYx0jUjA/g678pHHBc2lY7\n" +
            "dmL3abUwfweRxltZMkZDXSVnzwdywnUGIz1XsxETHnRnpDGgTKnn0wYix7zBFtNT\n" +
            "4mLczORoAoP8yrCDt64NsnFqGdaeltxTYEnTHZV5I30wI89YAnoH5y+wHL6OiNh7\n" +
            "qBjidq99QSFS0kBQBnvtHTDprQIDAQABo4IC8TCCAu0wOwYJKwYBBAGCNxUHBC4w\n" +
            "LAYkKwYBBAGCNxUIg4DSJ4GzrS+ZlxrppUGs9FSBZ4H8uW2EuYEfAgFlAgF4MB8G\n" +
            "A1UdJQQYMBYGCisGAQQBgjcUAgIGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIGwDAd\n" +
            "BgNVHQ4EFgQUFbhF8pcdgkFNlrTzwk+tHr/x2tQwHwYDVR0jBBgwFoAUPZPjtsSQ\n" +
            "Ro8fyiwzjNtRJPyH/XQwWAYDVR0fBFEwTzBNoEugSYZHaHR0cDovL3BraS5hZGNz\n" +
            "bGFib3IuZGUvQ2VydERhdGEvQURDUyUyMExhYm9yJTIwSXNzdWluZyUyMENBJTIw\n" +
            "MSgxKS5jcmwwggFdBggrBgEFBQcBAQSCAU8wggFLMIHIBggrBgEFBQcwAoaBu2xk\n" +
            "YXA6Ly8vQ049QURDUyUyMExhYm9yJTIwSXNzdWluZyUyMENBJTIwMSxDTj1BSUEs\n" +
            "Q049UHVibGljJTIwS2V5JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmln\n" +
            "dXJhdGlvbixEQz1pbnRyYSxEQz1hZGNzbGFib3IsREM9ZGU/Y0FDZXJ0aWZpY2F0\n" +
            "ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwUwYIKwYB\n" +
            "BQUHMAKGR2h0dHA6Ly9wa2kuYWRjc2xhYm9yLmRlL0NlcnREYXRhL0FEQ1MlMjBM\n" +
            "YWJvciUyMElzc3VpbmclMjBDQSUyMDEoMikuY3J0MCkGCCsGAQUFBzABhh1odHRw\n" +
            "Oi8vb2NzcC5hZGNzbGFib3IuZGUvb2NzcDAyBgNVHREEKzApoCcGCisGAQQBgjcU\n" +
            "AgOgGQwXcnVkaUBpbnRyYS5hZGNzbGFib3IuZGUwTgYJKwYBBAGCNxkCBEEwP6A9\n" +
            "BgorBgEEAYI3GQIBoC8ELVMtMS01LTIxLTEzODExODYwNTItNDI0NzY5MjM4Ni0x\n" +
            "MzU5MjgwNzgtMTIyNTANBgkqhkiG9w0BAQsFAAOCAgEAdfez2lwMm1XLRG/K6inn\n" +
            "D38XXZqFN8JPHJk4wpVUIAuFHF7+FPRdJaDD/rfk651bDYrQnzwgXCXa0qqvS2oa\n" +
            "NE5dVU7ZUJxOAkjqLZOZPzgDWPfwtModlABHhviVlY2ydKLzSMJfgiItqDFjYk4n\n" +
            "IZlQyydpXZxf1jirdsATnInDuqS/5BJlMRYYeO7K7p7HqPFqwZ138OIXNmK9EBNo\n" +
            "8qJsgTE9qn29VJOKUnBuwyHhewRSOIgL5oJz7aHqNmQsVQSeUO7uN/LAbAfPNCgS\n" +
            "/V3LL9S4tHytYY0JhxsmRA1eKWtlNkZG7cKmhf2Dsl5XlrOgkqDwNyPjuSC+55Tp\n" +
            "5fUm+XCdxiRkHggl7KDZoQP0UTjBT0mgQyvwINPegfA2F157n2BwnDjaiFLv1u+H\n" +
            "bPPn7Yo1SICtxcPQv+J3cszcZl8T9aD0cXSd/s+9Noazy9ZriD5nrQG0uqJSCHUp\n" +
            "xO1iKP2smz5M4ByMrFI3ljbGpbfuS6blcVwNduxZpgTNLmj/rZk+B+frXfJxFL1k\n" +
            "TYJKA4GLLAUIOybPeydNDTHs+RlFQXT0WUg91TBtW2CnHQJKajw/EScWmVX9Az2f\n" +
            "XIL/KQnR9dBqGSyJ1ttOZ6DH8ybE7IusRjkJUjZdRLiwxsmDhzWd9nQEkedbrRUM\n" +
            "62tj3XcrgHpTt6ugnRxsj8cxggG3MIIBswIBATCBizB0MQswCQYDVQQGEwJERTEQ\n" +
            "MA4GA1UECBMHQmF2YXJpYTEPMA0GA1UEBxMGTXVuaWNoMRMwEQYDVQQKEwpBRENT\n" +
            "IExhYm9yMQswCQYDVQQLEwJJVDEgMB4GA1UEAxMXQURDUyBMYWJvciBJc3N1aW5n\n" +
            "IENBIDECE3MACA5a1PvJHzNcjRkAAgAIDlowDQYJYIZIAWUDBAIBBQAwDQYJKoZI\n" +
            "hvcNAQEBBQAEggEAlJVSq7hr7o17x8WavmELZoleLOYcaB3txm1+x27fakz9IlDg\n" +
            "zO3Re8WyXEwd44Ykjc5RtzGXlmBUBup7TrF84TodqZjmXjmY+tuvaboS76L5PhMq\n" +
            "VHbwcjWIdKRy/OMH00aMDLQyd2sC+xsIR4YqWA2fVBPHYZq4uZ4Qnfmg9A2NLDGM\n" +
            "xyAmX6eN2uC/jgMRaAbWrEI63R4nHBlZWBPel/GgwOc5HUc2vSCJzC1QrD/tRvuz\n" +
            "p7wxv0zUScBB8ZrMfTP9miCcnL/k3t6LKscION3KB9aqjlU4DZDZQ2eopQKkFqHJ\n" +
            "ivMQZOGuu4Ri/tn7IY5KGOKQjuXh0aMzklATuQ==\n" +
            "-----END PKCS #7 SIGNED DATA-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS7);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.Equal(WinError.CERT_E_INVALID_NAME, result.StatusCode);
    }

    [Fact]
    public void Deny_commonName_invalid_dnsName_invalid_CMC_encoded()
    {
        // CN=this-is-a-test
        // dnsName=this-is-a-test
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIGOQYJKoZIhvcNAQcCoIIGKjCCBiYCAQMxCzAJBgUrDgMCGgUAMIIEkwYIKwYB\n" +
            "BQUHDAKgggSFBIIEgTCCBH0wZDBiAgECBgorBgEEAYI3CgoBMVEwTwIBADADAgEB\n" +
            "MUUwQwYJKwYBBAGCNxUUMTYwNAIBBQwaQ0xJRU5UMi5pbnRyYS5hZGNzbGFib3Iu\n" +
            "ZGUMCklOVFJBXHJ1ZGkMB01NQy5FWEUwggQPoIIECwIBATCCBAQwggLsAgEAMBkx\n" +
            "FzAVBgNVBAMMDnRoaXMtaXMtYS10ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n" +
            "MIIBCgKCAQEA6hJzcbbvMbAnlwkTKtXWy8CfSGAuQraUFpPrFRUVBWjkKHUAIz+Q\n" +
            "T0TLNLQ82civl3ajzy0KaCCKNXNL3h7I4mfRFl4Vz7Yx+cA/GrUfUXRXbwDZV4wA\n" +
            "mkuBMoXep3rFXzrBgv2DMv7P55FKwAYuyQ5wIGrkWyquU+VnDxhHTUDQXm9dQ4cG\n" +
            "ERjlbOkM9kgEjde8s1Ws3YvMtwOGm1bnFTLo80jhaIDiBrvahj3oJoya0bupLJVT\n" +
            "L4fypkk8H0ztT3/5O/n8CqxmavDVNzMmVl9SMnQlUtct2gJzx9+vnXc+eGRrp2hC\n" +
            "0lfznnVfwNDv7+xTxYLUz9rIFRXZDPcasQIDAQABoIIBpDAcBgorBgEEAYI3DQID\n" +
            "MQ4WDDEwLjAuMTgzNjMuMjBDBgkrBgEEAYI3FRQxNjA0AgEFDBpDTElFTlQyLmlu\n" +
            "dHJhLmFkY3NsYWJvci5kZQwKSU5UUkFccnVkaQwHTU1DLkVYRTByBgorBgEEAYI3\n" +
            "DQICMWQwYgIBAR5aAE0AaQBjAHIAbwBzAG8AZgB0ACAAUgBTAEEAIABTAEMAaABh\n" +
            "AG4AbgBlAGwAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBp\n" +
            "AGQAZQByAwEAMIHKBgkqhkiG9w0BCQ4xgbwwgbkwOwYJKwYBBAGCNxUHBC4wLAYk\n" +
            "KwYBBAGCNxUIg4DSJ4GzrS+ZlxrppUGs9FSBZ4b521KEm4hwAgFkAgEQMBMGA1Ud\n" +
            "JQQMMAoGCCsGAQUFBwMBMA4GA1UdDwEB/wQEAwIFoDAbBgkrBgEEAYI3FQoEDjAM\n" +
            "MAoGCCsGAQUFBwMBMBkGA1UdEQQSMBCCDnRoaXMtaXMtYS10ZXN0MB0GA1UdDgQW\n" +
            "BBQglePw4hbDLawtDYHqDTdx9rMwAjANBgkqhkiG9w0BAQUFAAOCAQEAtNAv5hgi\n" +
            "zE9Db9u6Wfp4I3l9MC1cwr/IDwvqt72MQ17487DgPLwx8UVTVB2SJDKPOEE8y4BT\n" +
            "T7o/FN8R+lE6SxpGtOufp+r8GKSiUpLJCcdHIqnrPgHO8GBo0u7arCKPyGY7tJ3e\n" +
            "xAAcJlji2mGf/cZe30gRNH4vBvBpuhxzccFWyEAigpF1WhvO1V9nvaZEeZlDPWAJ\n" +
            "NPZvtXsFGQeikrmRnR3uFJ/jtgWBdC9k8Q9huuNv8Bvccj8qYWL/Mtq7DvJQTXSS\n" +
            "2ZnYd5daMmaMwR4PTSMJBL39dcOO13E8V96zNVzk0vyuGV6aj6PYbYG1mcBYhRYo\n" +
            "yGjpsGJCDObrsDAAMAAxggF7MIIBdwIBA4AUIJXj8OIWwy2sLQ2B6g03cfazMAIw\n" +
            "CQYFKw4DAhoFAKA+MBcGCSqGSIb3DQEJAzEKBggrBgEFBQcMAjAjBgkqhkiG9w0B\n" +
            "CQQxFgQUxhKbjHHGqjcaR+dFE/O6k3U0uiMwDQYJKoZIhvcNAQEBBQAEggEA1IqJ\n" +
            "eY7zq0pTPOw2Ejja946kFRgKeRGyFz6tefs8WZs+FVStA0y31o7Lirnz5ipb51hv\n" +
            "vD+J4vWPJzamqlf+XuL3LcqGE2yzmiqPClhdSOnS1YxOup26688NCLPbEXfjYWYL\n" +
            "IKI6SlYKfyl94LSGnZHzK4S7tVxcZ1neXh6b9VgOO4UfyXPWrsPNBfKPJffXkBVb\n" +
            "vTRD/rXcqWn+SM4iTNGbcIMVZdIfMsug1N4twwUrullFrzBcY46FZB2Ht5jFmxHf\n" +
            "b+xocnI5ehrg/rjE9FaCSc63/6vUmwZTg/AhnvYpgWUKjXbfMHa/HtnJnTFRU/Ts\n" +
            "Q2DN9dMpV1FjWqNXdA==\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_CMC);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, _policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.Equal(WinError.CERT_E_INVALID_NAME, result.StatusCode);
    }

    [Fact]
    public void Deny_commonName_ip_disallowed()
    {
        var policy = _policy;

        policy.Subject.Clear();

        policy.Subject.Add(
            new SubjectRule
            {
                Field = RdnTypes.CommonName,
                Mandatory = true,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"192.168.0.0/16", TreatAs = PatternType.CIDR }
                }
            }
        );

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.Equal(WinError.CERT_E_INVALID_NAME, result.StatusCode);
    }

    [Fact]
    public void Deny_commonName_ip_invalid()
    {
        var policy = _policy;

        policy.Subject.Clear();

        policy.Subject.Add(
            new SubjectRule
            {
                Field = RdnTypes.CommonName,
                Mandatory = true,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"test", TreatAs = PatternType.CIDR },
                    new() { Expression = @"test/0", TreatAs = PatternType.CIDR },
                    new() { Expression = @"0.0.0.0/test", TreatAs = PatternType.CIDR }
                }
            }
        );

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.Equal(WinError.CERT_E_INVALID_NAME, result.StatusCode);
    }

    [Fact]
    public void Allow_notAfter_valid()
    {
        var policy = _policy;
        var notAfter = "2100-12-31T23:59:59.0000000+01:00";
        policy.NotAfter = notAfter;

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);
        var previousNotAfter = result.NotAfter;

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.False(result.DeniedForIssuance);
        Assert.Equal(WinError.ERROR_SUCCESS, result.StatusCode);

        Assert.True(result.NotAfter.Equals(DateTimeOffset.ParseExact(notAfter, "o",
            CultureInfo.InvariantCulture.DateTimeFormat,
            DateTimeStyles.AssumeUniversal)) || result.NotAfter == previousNotAfter);
    }

    [Fact]
    public void Deny_notAfter_invalid()
    {
        var policy = _policy;
        policy.NotAfter = "ThisIsNotAValidDateTime";

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.Equal(WinError.ERROR_INVALID_TIME, result.StatusCode);
    }

    [Fact]
    public void Deny_duplicate_SubjectRule_of_same_type_in_Subject()
    {
        var policy = _policy;

        policy.Subject.Clear();

        policy.Subject.Add(
            new SubjectRule
            {
                Field = RdnTypes.CommonName,
                Mandatory = true,
                MaxOccurrences = 1,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"^intranet\.adcslabor\.de$" }
                }
            }
        );

        policy.Subject.Add(
            new SubjectRule
            {
                Field = RdnTypes.CommonName,
                Mandatory = true,
                MaxOccurrences = 1,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"^intranet\.adcslabor\.de$" }
                }
            }
        );

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.NTE_FAIL));
    }

    [Fact]
    public void Deny_duplicate_SubjectRule_of_same_type_in_SubjectAlternativeName()
    {
        var policy = _policy;

        policy.Subject.Clear();

        policy.SubjectAlternativeName.Add(
            new SubjectRule
            {
                Field = SanTypes.DnsName,
                Mandatory = true,
                MaxOccurrences = 1,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"^intranet\.adcslabor\.de$" }
                }
            }
        );

        policy.SubjectAlternativeName.Add(
            new SubjectRule
            {
                Field = SanTypes.DnsName,
                Mandatory = true,
                MaxOccurrences = 1,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"^intranet\.adcslabor\.de$" }
                }
            }
        );

        var dbRow = new CertificateDatabaseRow(_request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.NTE_FAIL));
    }

    [Fact]
    public void Deny_duplicate_RDN_with_same_value()
    {
        var policy = _policy;

        policy.Subject.Clear();

        policy.Subject.Add(
            new SubjectRule
            {
                Field = RdnTypes.CommonName,
                Mandatory = true,
                MaxOccurrences = 2,
                Patterns = new List<Pattern>
                {
                    new() { Expression = @"^(intranet|extranet)\.adcslabor\.de$" }
                }
            }
        );

        // 2048 Bit RSA Key
        // CN=intranet.adcslabor.de,CN=intranet.adcslabor.de
        const string request =
            "-----BEGIN NEW CERTIFICATE REQUEST-----\n" +
            "MIIEkTCCAvkCAQAwQDEeMBwGA1UEAxMVaW50cmFuZXQuYWRjc2xhYm9yLmRlMR4w\n" +
            "HAYDVQQDExVpbnRyYW5ldC5hZGNzbGFib3IuZGUwggGiMA0GCSqGSIb3DQEBAQUA\n" +
            "A4IBjwAwggGKAoIBgQDDPNibfYz+vlr4aLtpKPHncxDI6AnxMJF8ExEQldS/1e+R\n" +
            "L7GVQYLnGNWHeqjjT0LtQAQjEqt/yMkUWpRPodQgyRRQcplKih9CexyLfbf2Gn6D\n" +
            "Q0js7Am1iuFN/ApiWFvcm7M7bFiaSIr/m2UG9fLQMB3lK+ZmOISBOdsxO5CC4YHM\n" +
            "ot3JvbWl0kfdAEFAPma+kcL32+Gz4HP6SSh4IqQnRu3YkMLq4gNN0zzF76wdMj8/\n" +
            "mL8MGUe2Zl478jqAP3xhQKCoqgG1tFcF0gpDr7gjjeIKT535qXOG0hX4UIV53cak\n" +
            "SKEitxbXPHvxl7hWXUvI1vk0uRRM06FLI5xfzGoCMrjyKLEPJxfE7oRzeS1YZoKl\n" +
            "PVflNOvoO8I9qr2n/kK+K8Qg9ntUt1lH0CMiLVhYKVuv4O9dRS73miNJV20aHmDn\n" +
            "XYqfcLkqUi9AfNm5gUDe+FVke6Pb+NiB09dVGZxm0g1WvWO2nKSd0Ps4MawParlQ\n" +
            "a8we23T/ZFdo5UVJw5ECAwEAAaCCAQowHAYKKwYBBAGCNw0CAzEOFgwxMC4wLjI2\n" +
            "MTAwLjIwPgYJKoZIhvcNAQkOMTEwLzAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYE\n" +
            "FFRbOjCUNSRJLgKaDT9h7SviNI7SMEIGCSsGAQQBgjcVFDE1MDMCAQUMBkRFVi1Q\n" +
            "QwwWQXp1cmVBRFxVd2VHcmFkZW5lZ2dlcgwOcG93ZXJzaGVsbC5leGUwZgYKKwYB\n" +
            "BAGCNw0CAjFYMFYCAQAeTgBNAGkAYwByAG8AcwBvAGYAdAAgAFMAbwBmAHQAdwBh\n" +
            "AHIAZQAgAEsAZQB5ACAAUwB0AG8AcgBhAGcAZQAgAFAAcgBvAHYAaQBkAGUAcgMB\n" +
            "ADANBgkqhkiG9w0BAQsFAAOCAYEANrCTZD67D47YfHeeLkZxjRr374aBMXhunFEB\n" +
            "iSMurfSRyCrZdLPGJDb+YuzT7mWnOlYUUggJz3WeTdS6Meq22wPNti/9ELGh0Cm5\n" +
            "v7I8INtC2KXa/i0LsBlP41XFOGX1D77zh6ZOKa1S4nJmchQgeot+xrrsqaXQ74st\n" +
            "Tt5oDSwB9c5aq67QiCS7cgu/9vFbyicGdjw1MvxL9HFBBxjOmF+GMhJy4eqqq/nH\n" +
            "GI/a9O1lKO4TS4tmJFB1wvUMBHc2lRrZv+99EjQVkyqg1W7T1cFVNhnEJgc38x5I\n" +
            "wUHVr95LwWgYzkVzPtxDE+cmFkayxcdx6BHR/7c/MawXtBlpC9FVdDwlwJISOtu3\n" +
            "ZfnqyyyUSAT7L2IatXiE5Q0gVJDvSzYLjKq76HwthSIXrQaTniVtHNPoYsTqZevX\n" +
            "FtW5/p8p33xmZ7PJUkIG2ddEdO3kjz1h2DGtPxy2cdnzWjgYke1dDyuxxi5hX6Fq\n" +
            "z9En0ZWry8gm+WaW24sNRxTR3Pkt\n" +
            "-----END NEW CERTIFICATE REQUEST-----";

        var dbRow = new CertificateDatabaseRow(request, CertCli.CR_IN_PKCS10);

        var result = new CertificateRequestValidationResult(dbRow);

        result = _validator.VerifyRequest(result, policy, dbRow, _template);

        PrintResult(result);

        Assert.True(result.DeniedForIssuance);
        Assert.True(result.StatusCode.Equals(WinError.CERT_E_INVALID_NAME));
    }
}