# Your first PLC

From a fresh gateway to a client that writes through it. Secure connections
need trust both ways, so a few steps go back and forth between the gateway
and the PLC.

1. **Gateway name** (Docker, or clients on other machines): Settings →
   Gateway certificate → **Host names and IP addresses**: the name or IP
   clients use to reach the gateway. Then Certificates → **Regenerate**. Do
   this before the PLC trusts the certificate, or it must trust it again.
2. **Add the target:** Targets → **Add target**: a name, where clients
   connect (`0.0.0.0:4841`; in Docker, publish that port), and the PLC's
   endpoint URL (`opc.tcp://192.168.0.10:4840`). **Check now** shows whether
   the gateway reaches the PLC.
3. **Gateway trusts the PLC:** on the target, **Trust…** the PLC certificate
   (compare the thumbprint with the PLC's).
4. **PLC trusts the gateway:** Certificates → **Download** the gateway
   certificate and add it to the PLC's trusted certificates. Many servers put
   the gateway's certificate in a `rejected` folder at the first attempt;
   moving it to `trusted` does it. The target then shows no trust problem.
5. **Minimum security:** edit the target and set the lowest security clients
   may use, e.g. **Sign & encrypt only**.
6. **Clients:** point them at `opc.tcp://<gateway>:4841` instead of the PLC.
   A client with a certificate lands under Certificates → **Waiting for a
   decision**: **Trust** it.
7. **Lock the PLC:** let the PLC trust only the gateway, so no client can go
   around it.

Writes now show up in the **Audit trail**. More: [Targets](targets.md),
[Certificates](certificates.md).
