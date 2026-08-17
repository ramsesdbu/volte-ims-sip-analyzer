import pandas as pd


class SIPParser:

    SIP_METHODS = [
        "REGISTER",
        "INVITE",
        "ACK",
        "BYE",
        "CANCEL",
        "OPTIONS",
        "MESSAGE",
        "INFO",
        "UPDATE",
        "PRACK",
        "SUBSCRIBE",
        "NOTIFY",
        "REFER",
        "PUBLISH"
    ]

    def parse(self, packets):

        records = []

        for frame_no, packet in enumerate(packets, start=1):

            if not packet.haslayer("Raw"):
                continue

            try:
                payload = bytes(packet["Raw"]).decode(
                    errors="ignore"
                )

            except Exception:
                continue

            lines = payload.split("\r\n")

            if len(lines) == 0:
                continue

            first_line = lines[0].strip()

            ##################################################
            # Detect SIP Request
            ##################################################

            sip_type = ""
            method = ""
            response_code = ""
            response_text = ""

            if first_line.startswith("SIP/2.0"):

                sip_type = "Response"

                temp = first_line.split(" ", 2)

                if len(temp) >= 2:
                    response_code = temp[1]

                if len(temp) >= 3:
                    response_text = temp[2]

            else:

                first_word = first_line.split(" ")[0]

                if first_word not in self.SIP_METHODS:
                    continue

                sip_type = "Request"
                method = first_word

            ##################################################
            # Header Parsing
            ##################################################

            header = {}

            for line in lines[1:]:

                if ":" not in line:
                    continue

                key, value = line.split(":", 1)

                header[key.strip()] = value.strip()

            ##################################################
            # Record
            ##################################################

            records.append({

                "Frame": frame_no,

                "Time":
                float(packet.time),

                "Source":
                packet["IP"].src if packet.haslayer("IP") else "",

                "Destination":
                packet["IP"].dst if packet.haslayer("IP") else "",

                "Transport":
                "UDP" if packet.haslayer("UDP")
                else "TCP" if packet.haslayer("TCP")
                else "",

                "Type":
                sip_type,

                "Method":
                method,

                "Response Code":
                response_code,

                "Response Text":
                response_text,

                "Call-ID":
                header.get("Call-ID", ""),

                "CSeq":
                header.get("CSeq", ""),

                "From":
                header.get("From", ""),

                "To":
                header.get("To", ""),

                "Via":
                header.get("Via", ""),

                "Contact":
                header.get("Contact", ""),

                "User-Agent":
                header.get("User-Agent", ""),

                "Content-Type":
                header.get("Content-Type", ""),

                "Content-Length":
                header.get("Content-Length", "")

            })

        return pd.DataFrame(records)

    ##########################################################

    def statistics(self, df):

        if df.empty:

            return {}

        stats = {}

        ##################################################

        stats["total"] = len(df)

        ##################################################

        request = df[df["Type"] == "Request"]

        response = df[df["Type"] == "Response"]

        stats["request"] = len(request)

        stats["response"] = len(response)

        ##################################################

        for m in self.SIP_METHODS:

            stats[m] = len(
                request[
                    request["Method"] == m
                ]
            )

        ##################################################

        response_codes = [
            "100",
            "180",
            "183",
            "200",
            "202",
            "302",
            "400",
            "401",
            "403",
            "404",
            "408",
            "480",
            "481",
            "486",
            "487",
            "488",
            "500",
            "501",
            "503",
            "504",
            "603"
        ]

        for code in response_codes:

            stats[code] = len(

                response[
                    response["Response Code"] == code
                ]

            )

        ##################################################

        stats["Unique Call-ID"] = df[
            "Call-ID"
        ].replace(
            "",
            pd.NA
        ).dropna().nunique()

        ##################################################

        stats["Unique User-Agent"] = df[
            "User-Agent"
        ].replace(
            "",
            pd.NA
        ).dropna().nunique()

        ##################################################

        return stats
