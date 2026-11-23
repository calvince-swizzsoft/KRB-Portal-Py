from zeep import Client, Settings
from zeep.transports import Transport
from requests import Session
from requests.auth import HTTPBasicAuth
import os
import random
import string
import hashlib
import json
import base64
import re
from zeep.helpers import serialize_object

WSDL_URL = os.environ['PORTAL_WSDL_URL']
USERNAME = os.environ['PORTAL_SOAP_USERNAME']
PASSWORD = os.environ['PORTAL_SOAP_PASSWORD']

def get_member_account_statistics(member_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.MemberAccountStatistics(memberNo=member_no)
        raw_json = str(result).strip()

        if not raw_json:
            return {"error": "No data returned"}

        statistics = json.loads(raw_json)
        return statistics

    except json.JSONDecodeError:
        return {"error": "Invalid JSON format in SOAP response"}
    except Exception as e:
        return {"error": f"Failed to fetch member account statistics: {str(e)}"}



def generate_password():
    """Generate a 4-digit numeric password."""
    return ''.join(random.choices('0123456789', k=4))


def register_member(member_no, id_no):
    session = Session()

    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=10)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        new_password = generate_password()
        smsport = f"Your one-time pass key is {new_password}. You can change it to your liking."

        result = client.service.fnUpdatePassword(
            memberNo=member_no,
            idNo=id_no,
            newPassword=new_password,
            smsport=smsport
        )

        if result is True:
            return {
                "status": "success",
                "message": "Member registered successfully",
                "temporary_password": new_password,
                "service_response": result
            }
        else:
            return {
                "status": "fail",
                "message": "Member not registered",
                "service_response": result
            }

    except Exception as e:
        return {"error": str(e)}


def generate_otp():
    return str(random.randint(1000, 9999))

def send_otp(member_number):
    otp_code = generate_otp()

    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        response = client.service.fnSendOTPCode(memberNumber=member_number, otpCode=otp_code)

        return {
            "message": "OTP sent successfully",
            "otp": otp_code,
            "rawResponse": response
        }

    except Exception as e:
        return {"error": str(e)}


def confirm_otp(member_number, otp_code):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        ok = client.service.fnConfirmOTPCode(memberNumber=member_number, otpCode=otp_code)

        if ok is True:
            return {"status": "success", "message": "OTP confirmed successfully"}
        else:
            # failed or expired
            return {"status": "fail", "message": "OTP confirmation failed: wrong or expired code."}

    except Exception as e:
        return {"status": "error", "message": str(e)}





def hash_password(password):
    """Hash and truncate to 25 characters (if required)."""
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    return sha256_hash[:25]

def login_member(username, password): 
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        # Hash the password before sending
        hashed_pass = hash_password(password)

        result = client.service.Fnlogin(
            username=username,
            password=hashed_pass
        )

        login_success = str(result).strip().lower() == "true"

        return {"authenticated": login_success}

    except Exception as e:
        return {"error": f"Login failed: {str(e)}"}


def hash_password(password):
    """Hash and truncate to 25 characters (if required)."""
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()
    return sha256_hash[:25]

def change_password(member_number, current_pass, new_pass):
    session = Session()

    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=10)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        # Only hash the new password
        hashed_new_pass = hash_password(new_pass)

        result = client.service.fnChangePassword(
            memberNumber=member_number,
            currentPass=current_pass,      # PLAIN
            newPass=hashed_new_pass        # HASHED
        )

        return {
            "status": "success",
            "message": "Password changed successfully",
            "service_response": result
        }
    except Exception as e:
        return {"error": str(e)}

def get_member_profile(member_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=10)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        # 1) Fetch Member Profile
        response = client.service.FnGetMemberProfile(memberNo=member_no)
        return_value = (getattr(response, "return_value", response) or "").strip()
        main_part, separator, image_data = return_value.rpartition(":")
        if not separator or not main_part:
            return {"status": "error", "message": "Member profile is unavailable"}

        # The versioned suffix leaves legacy profile fields and the final photo in place.
        document_fields = main_part.rsplit(":", 4)
        id_front, id_back, kra_document = "", "", ""
        if len(document_fields) == 5 and document_fields[1] == "PROFILE_DOCUMENTS_V1":
            main_part, _, id_front, id_back, kra_document = document_fields

        parts = [p.strip() for p in main_part.split(":")]

        profile_data = {
            "MemberNumber": parts[0] if len(parts)>0 else "",
            "FullName":     parts[1] if len(parts)>1 else "",
            "Email":        parts[2] if len(parts)>2 else "",
            "Status":       parts[3] if len(parts)>3 else "",
            "Phone":        parts[4] if len(parts)>4 else "",
            "IDNumber":     parts[5] if len(parts)>5 else "",
            "PayrollNumber":parts[7] if len(parts)>7 else "",
            "KRAPin":       parts[9] if len(parts)>9 else "",
            "NHIFNumber":   parts[10] if len(parts)>10 else "",
            "JoinDate":     parts[12] if len(parts)>12 else "",
            "ImageBase64": image_data.strip(),
            "IdFrontBase64": id_front.strip(),
            "IdBackBase64": id_back.strip(),
            "KraPinDocumentBase64": kra_document.strip(),
        }

        # 2) Fetch Next of Kin
        kin_result = get_next_of_kin(member_no)
        next_of_kin = kin_result.get("next_of_kin", [])

        # 3) Fetch Nominees
        nom_result = get_member_nominees(member_no)
        nominees = nom_result.get("nominees", [])

        return {
            "status":       "success",
            "profile":      profile_data,
            "next_of_kin":  next_of_kin,
            "nominees":     nominees
        }

    except Exception as e:
        return {
            "status":  "error",
            "message": f"Failed to fetch member profile: {str(e)}",
            "profile": None,
            "next_of_kin": [],
            "nominees": []
        }







def encode_image_to_base64(image_path):
    """Encode an image file to a base64 string."""
    with open(image_path, "rb") as image_file:
        return base64.b64encode(image_file.read()).decode("utf-8")


def edit_member_details(member_number, full_names, phone_number, email, id_number, kra_pin,
                        image_blob, kra_pin_doc_pic, id_front, id_back):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnEditMemberDetails(
            memberNumber=member_number,
            fullNames=full_names,
            phoneNumber=phone_number,
            email=email,
            iDNumber=id_number,
            kRAPin=kra_pin,
            imageBlob=image_blob,
            kRAPinDocumentPic=kra_pin_doc_pic,
            idFront=id_front,
            idBack=id_back
        )

        return {"success": result}

    except Exception as e:
        return {"error": str(e)}







def get_member_account_details(member_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=10)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.MemberAccountDetails(memberNo=member_no)
        return json.loads(result)
    except Exception as e:
        return {"error": f"Failed to fetch member account details: {str(e)}"}



def get_loan_guarantors_pdf(member_no, filter_text, big_text):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnLoanGurantorsReport(
            memberNo=member_no,
            filter=filter_text,
            bigText=big_text
        )

        # The result is a base64-encoded PDF
        pdf_data = base64.b64decode(result)

        return pdf_data

    except Exception as e:
        return {"error": str(e)}


def get_loan_guaranteed_pdf(member_no, filter_text, big_text):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnLoanGuranteed(
            memberNo=member_no,
            filter=filter_text,
            bigText=big_text
        )

        # The result is a base64-encoded PDF
        pdf_data = base64.b64decode(result)

        return pdf_data

    except Exception as e:
        return {"error": str(e)}


def get_member_sharecertificate_pdf(member_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        soap_response = client.service.fnSharesCertificate(
            memberNo=member_no
        )

        if isinstance(soap_response, str):
            base64_pdf = soap_response
            
        elif hasattr(soap_response, 'return_value'):
            base64_pdf = soap_response.return_value
            
        elif isinstance(soap_response, (list, tuple)) and len(soap_response) > 0:
            base64_pdf = soap_response[0]
            
        else:
            return {
                "error": "Unexpected SOAP response format",
                "details": {
                    "response_type": str(type(soap_response)),
                    "response_attrs": dir(soap_response)
                }
            }

        base64_pdf = base64_pdf.strip()
        if not base64_pdf:
            return {"error": "Empty PDF data received"}

        try:
            pdf_data = base64.b64decode(base64_pdf)
            return pdf_data
        except Exception as e:
            return {"error": f"Base64 decoding failed: {str(e)}"}

    except Exception as e:
        return {"error": f"SOAP call failed: {str(e)}"}        


def get_running_loans(member_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=10)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnRunningLoans(memberNumber=member_no)

        if not result:
            return []

        return json.loads(result)
    except Exception as e:
        return {"error": f"Failed to fetch running loans: {str(e)}"}


def get_member_detailed_statement_pdf(member_no, filter_text):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnMemberStatement(
            memberNo=member_no,
            filter=filter_text,
        )

        pdf_data = base64.b64decode(result)
        return pdf_data

    except Exception as e:
        return {"error": str(e)}




def get_member_deposit_statement_pdf(member_no, filter_text):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnMemberDepositStatement(
            memberNo=member_no,
            filter=filter_text,
        )
        print(f"[DEBUG] SOAP Response: {result}")  # Log raw response

        if result is None:
            return {"error": "SOAP API returned None"}

        pdf_data = base64.b64decode(result)
        return pdf_data

    except Exception as e:
        return {"error": str(e)}



def get_loan_statement_pdf(member_no, filter_text, big_text):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.FnLoanStatement(
            memberNo=member_no,
            filter=filter_text,
            bigText=big_text
        )

        base64_pdf = result.return_value  

        pdf_data = base64.b64decode(base64_pdf)

        return pdf_data

    except Exception as e:
        return {"error": str(e)}


def get_loan_products_with_details():
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        # Call the service - result is a raw string containing all loan info
        result = client.service.FnLoansSetup()

        if not result or "!!" not in result:
            return {"error": "Unexpected or empty response from loan service"}

        loan_lines = [line.strip() for line in result.split("??") if line.strip()]
        loan_products = []

        for line in loan_lines:
            try:
                code_part, rest = line.split(":", 1)
                details = rest.split("!!")

                if len(details) < 6:
                    continue  

                loan_products.append({
                    "loan_code": code_part.strip(),
                    "product_description": details[0].strip(),
                    "repayment_type": details[1].strip(),
                    "max_amount": details[2].strip(),
                    "term": details[3].strip(),
                    "interest_rate": details[4].strip(),
                    "repayment_frequency": details[5].strip()
                })
            except Exception as e:
                continue

        return loan_products

    except Exception as e:
        return {"error": f"Service call failed: {str(e)}"}





def apply_for_loan(
    bosa_no, loan_type, loan_amount, loan_purpose,
    repayment_period, disbursement_mode, recovery_mode, account_or_mpesa_no,
    member_bank
):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        print(f"\n{'='*50}")
        print("STEP 1: Fetching loan product details...")
        print(f"Loan Type: {loan_type}")
        
        product_details = client.service.FnGetLoanProductDetails(productType=loan_type)
        print(f"Product details response: {product_details}")
        
        parts = product_details.split(":::")
        if len(parts) != 4:
            error_msg = "Invalid loan product configuration"
            print(f"ERROR: {error_msg}")
            return {"status": "error", "message": error_msg}

        min_amount = float(parts[0].replace(",", "").strip())
        max_amount = float(parts[1].replace(",", "").strip())
        max_installments = int(parts[3].strip())
        
        print(f"Product validation:")
        print(f"  Min Amount: {min_amount}")
        print(f"  Max Amount: {max_amount}")
        print(f"  Max Installments: {max_installments}")

    except Exception as e:
        error_msg = f"Failed to fetch product details: {str(e)}"
        print(f"ERROR: {error_msg}")
        return {"status": "error", "message": error_msg}

    try:
        loan_amount = float(loan_amount)
        repayment_period = int(repayment_period)
    except:
        error_msg = "Loan amount and repayment period must be valid numbers"
        print(f"ERROR: {error_msg}")
        return {"status": "error", "message": error_msg}

    if loan_amount < min_amount:
        error_msg = f"Loan amount must be at least {min_amount}"
        print(f"ERROR: {error_msg}")
        return {"status": "error", "message": error_msg}
    
    if loan_amount > max_amount:
        error_msg = f"Loan amount must not exceed {max_amount}"
        print(f"ERROR: {error_msg}")
        return {"status": "error", "message": error_msg}
    
    if repayment_period > max_installments:
        error_msg = f"Repayment period exceeds max allowed: {max_installments} months"
        print(f"ERROR: {error_msg}")
        return {"status": "error", "message": error_msg}

    try:
        print(f"\n{'='*50}")
        print("STEP 2: Submitting loan application to SOAP API...")
        print("Loan Application Parameters:")
        print(f"  bosaNo: {bosa_no}")
        print(f"  loanType: {loan_type}")
        print(f"  loanAmount: {loan_amount}")
        print(f"  loanpurpose: {loan_purpose}")
        print(f"  repaymentPeriod: {repayment_period}")
        print(f"  disbursementMode: {disbursement_mode}")
        print(f"  recoveryMode: {recovery_mode}")
        print(f"  accountOrMpesaNo: {account_or_mpesa_no}")
        print(f"  memberBank: {member_bank}")
        
        response = client.service.OnlineLoanApplication(
            bosaNo=bosa_no,
            loanType=loan_type,
            loanAmount=loan_amount,
            loanpurpose=loan_purpose,
            repaymentPeriod=repayment_period,
            disbursementMode=disbursement_mode,
            recoveryMode=recovery_mode,
            accountOrMpesaNo=account_or_mpesa_no,
            memberBank=member_bank
        )

        message = str(response).strip()
        message_upper = message.upper()
        
        print(f"\n{'='*50}")
        print("SOAP API RESPONSE:")
        print(f"Raw message: {message}")
        print(f"Message length: {len(message)} chars")
        print(f"Is numeric/loan-like: {message.isalnum() and len(message) <= 20}")

        # Check if response looks like a loan number (e.g., "PLN030", "LN1270")
        if message and message.isalnum() and len(message) <= 20:
            print(f"\n✅ LOAN APPLICATION SUCCESSFUL!")
            print(f"Loan Number received: {message}")
            
            # If it looks like a loan number, treat it as success
            # Check if it might be an error code (starts with ERROR, FAILED, etc)
            if any(error_word in message_upper for error_word in ["ERROR", "FAILED", "INVALID", "REJECTED"]):
                print(f"❌ Looks like an error code")
                return {
                    "status": "error",
                    "message": message
                }
            else:
                # It's a loan number - success!
                return {
                    "status": "success",
                    "message": f"Loan application submitted successfully. Loan Number: {message}",
                    "loan_no": message  # The entire message is the loan number
                }
        
        # Check for explicit failure messages
        if "FAILED" in message_upper or "ERROR" in message_upper:
            print(f"\n❌ LOAN APPLICATION FAILED:")
            print(f"Error message: {message}")
            return {
                "status": "error",
                "message": message
            }
        elif "SUCCESS" in message_upper or "APPROVED" in message_upper or "PENDING" in message_upper:
            print(f"\n✅ LOAN APPLICATION SUCCESSFUL:")
            print(f"Success message: {message}")
            
            # For success messages, check if we can extract a loan number
            loan_no = None
            import re
            
            # Try to extract loan number from success message
            loan_no_match = re.search(r'LOAN\s*NO\s*[:=\-]?\s*([A-Z0-9]+)', message_upper)
            if loan_no_match:
                loan_no = loan_no_match.group(1)
                print(f"Extracted Loan Number: {loan_no}")
            
            return {
                "status": "success",
                "message": message,
                "loan_no": loan_no
            }
        else:
            # Unknown response - assume success if it doesn't look like an error
            print(f"\n⚠️  UNKNOWN RESPONSE - Assuming success:")
            print(f"Message: {message}")
            return {
                "status": "success",
                "message": message
            }

    except Exception as e:
        error_msg = f"Loan application failed: {str(e)}"
        print(f"\n❌ EXCEPTION IN LOAN APPLICATION:")
        print(f"Error: {error_msg}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return {"status": "error", "message": error_msg}


def get_member_existing_loans(bosa_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        response = client.service.GetMemberExistingLoans(bosaNo=bosa_no)

        data = response.strip()

        if not data or "no loans" in data.lower():
            return []

        loans = []

        # 🔥 1. Split by "??" to get each loan block
        loan_blocks = [x for x in data.split("??") if x.strip()]

        for block in loan_blocks:

            loan_dict = {}

            # 2. Split block by "!!" to get "loanNo:LN1115", "ProductName:DEVELOPMENT LOAN 1", etc.
            fields = block.split("!!")

            for field in fields:
                if ":" not in field:
                    continue

                key, value = field.split(":", 1)
                key = key.strip()
                value = value.strip()

                # Parse numbers that contain commas
                if key in ["Outstanding", "ArrearsAmt"]:
                    try:
                        loan_dict[key] = float(value.replace(",", ""))
                    except:
                        loan_dict[key] = 0.0
                elif key == "ArrearsDays":
                    try:
                        loan_dict[key] = int(value)
                    except:
                        loan_dict[key] = 0
                else:
                    loan_dict[key] = value

            # Add alias "Product"
            if "ProductName" in loan_dict:
                loan_dict["Product"] = loan_dict["ProductName"]

            if loan_dict.get("LoanNo"):
                loans.append(loan_dict)

        return loans

    except Exception as e:
        print("Error:", e)
        return {"error": str(e)}

def apply_loan_refinancing(bosa_no, loan_no, loan_top_up_no, loan_type, amount):
    """
    SOAP API call for loan refinancing/offsetting
    """
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        amount = float(amount)
        
        print(f"\n{'='*60}")
        print("🔄 REFINANCING SOAP API CALL")
        print(f"{'='*60}")
        print("Parameters:")
        print(f"  bosaNo: {bosa_no}")
        print(f"  loanNo (NEW loan): {loan_no}")
        print(f"  loanTopUpNo (EXISTING loan): {loan_top_up_no}")
        print(f"  loanType: {loan_type}")
        print(f"  amount: {amount}")
        
        # Try to map product name to code if needed
        product_mapping = {
            "INSTANT LOAN": "IL",
            "EMERGENCY LOAN": "EL",
            "SCHOOL FEES LOAN": "SFL",
            "DEVELOPMENT LOAN": "DL",
            "NORMAL LOAN": "NL",
            "IL": "IL",
            "EL": "EL",
            "SFL": "SFL",
            "DL": "DL",
            "NL": "NL"
        }
        
        # Use mapping or original loan_type
        loan_type_to_use = product_mapping.get(loan_type.upper().strip(), loan_type)
        print(f"  loanType (after mapping): {loan_type_to_use}")
        
        print(f"\nCalling SOAP API: OnlineLoanRefinancing...")
        response = client.service.OnlineLoanRefinancing(
            bosaNo=bosa_no,
            loanNo=loan_no,
            loanTopUpNo=loan_top_up_no,
            loanType=loan_type_to_use,
            amount=amount
        )
        
        message = str(response).strip()
        message_upper = message.upper()
        
        print(f"\nSOAP API Response:")
        print(f"  Raw message: {message}")
        print(f"  Message length: {len(message)} chars")
        print(f"  Contains 'SUCCESS': {'SUCCESS' in message_upper}")
        print(f"  Contains 'FAILED': {'FAILED' in message_upper}")
        print(f"  Contains 'ERROR': {'ERROR' in message_upper}")
        
        if "FAILED" in message_upper or "ERROR" in message_upper:
            print(f"\n❌ REFINANCING FAILED")
            print(f"Error message: {message}")
            return {
                "status": "error",
                "message": message
            }
        else:
            print(f"\n✅ REFINANCING SUCCESSFUL")
            print(f"Success message: {message}")
            return {
                "status": "success",
                "message": message
            }
            
    except Exception as e:
        error_msg = f"Loan refinancing failed: {str(e)}"
        print(f"\n❌ EXCEPTION IN REFINANCING:")
        print(f"Error: {error_msg}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return {"status": "error", "message": error_msg}


        
def get_online_applied_loans(member_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnOnlineLoans(memberNumber=member_no)

        if not result:
            return {"loans": []}

        loan_entries = result.strip().split("::;")
        loans = []

        for entry in loan_entries:
            parts = entry.strip().split(":::")
            if len(parts) >= 4:
                loans.append({
                    "loan_no": parts[0],
                    "amount": parts[1],
                    "status": parts[2],
                    "applied_date": parts[3]
                })

        return {"loans": loans}

    except Exception as e:
        return {"error": f"Failed to fetch online loans: {str(e)}"}


def edit_online_loan(loan_number, member_number, amount_request, loan_type, repayment_period):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        # Correct: Use loan_type, not loan_number
        product_details = client.service.FnGetLoanProductDetails(productType=loan_type)
        parts = product_details.strip().split(":::") if product_details else []

        if len(parts) != 4:
            return {"error": "Invalid product detail format returned by service"}

        try:
            min_amount = float(parts[0].replace(",", "").strip())
            max_amount = float(parts[1].replace(",", "").strip())
            max_repayment_period = int(parts[3].strip())
        except ValueError:
            return {"error": "Invalid number format in loan product details"}

        try:
            amount_request = float(amount_request)
            repayment_period = int(repayment_period)
        except ValueError:
            return {"error": "Amount and repayment period must be numeric"}

        # ✅ Collect multiple validation errors
        errors = []
        if amount_request < min_amount:
            errors.append(f"Requested amount must be at least {min_amount:,.2f}")
        if amount_request > max_amount:
            errors.append(f"Requested amount exceeds the maximum allowed ({max_amount:,.2f})")
        if repayment_period > max_repayment_period:
            errors.append(f"Repayment period exceeds maximum allowed ({max_repayment_period} months)")

        if errors:
            return {"errors": errors}

    except Exception as e:
        return {"error": f"Failed to fetch product details: {str(e)}"}

    # Step 2: Proceed to edit loan
    try:
        result = client.service.editOnlineLoan(
            loanNumber=loan_number,
            memberNumber=member_number,
            amountRequest=amount_request,
            loanType=loan_type,
            repaymentPeriod=repayment_period
        )

        if isinstance(result, dict):
            return result
        if isinstance(result, str):
            return {"message": result.strip()}

        return {"error": f"Unexpected response type: {type(result)}", "raw_result": str(result)}

    except Exception as e:
        return {"error": str(e)}


def guarantorship_policy(operation, *, raw=False, **parameters):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    client = Client(wsdl=WSDL_URL, transport=transport)
    result = getattr(client.service, operation)(**parameters)
    return result if raw else result is True


def request_guarantorship(member_number, loan_number, self_amount=None):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    
    try:
        client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)
        
        parameters = {"bosaNo": member_number, "loanNumber": loan_number, "response": ""}
        if self_amount is None:
            result = client.service.FnRequestGuarantorship(**parameters)
        else:
            result = client.service.FnRequestSelfGuarantee(amount=self_amount, **parameters)

        # Handle the response
        if hasattr(result, 'return_value') and result.return_value is True:
            return {
                "success": True,
                "message": result.response if hasattr(result, 'response') else "Success"
            }
        else:
            error_msg = result.response if hasattr(result, 'response') else "Request failed"
            return {
                "success": False,
                "message": error_msg
            }

    except Exception as e:
        import traceback
        error_msg = str(e)
        print(f"SOAP Error: {error_msg}")
        print(traceback.format_exc())
        return {"error": f"Failed to send request guarantorship: {error_msg}"}



def get_loan_guarantors(loan_no, member_number):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.FnGetGuarantors(
            loanNo=loan_no,
            memberNumber=member_number
        )

        raw_data = str(result).strip()

        if not raw_data:
            return {"guarantors": []}

        parsed = []
        for g in raw_data.split(":::"):
            g = g.strip()
            if g:
                try:
                    data = json.loads(g)
                    parsed.extend(data.get("OnlineGuarantors", []))
                except json.JSONDecodeError as e:
                    parsed.append({"error": f"Invalid JSON format: {str(e)}", "raw": g})

        return {"guarantors": parsed}

    except Exception as e:
        return {"error": f"Failed to fetch guarantors: {str(e)}"}



def approve_guarantorship(member_no, loan_no, approved_status, amount=None):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    
    try:
        client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)
        
        if approved_status == 0 and amount is not None:
            result = client.service.ApproveGuarantorshipWithAmount(
                memberNo=str(member_no), loanNo=str(loan_no), amount=amount
            )
        else:
            result = client.service.ApproveGuarantorship(
                memberNo=str(member_no), loanNo=str(loan_no), approvedStatus=approved_status
            )

        message = getattr(result, "return_value", result)
        if isinstance(message, str):
            normalized = message.strip().lower()
            expected = "true" if approved_status == 0 else "false"
            if normalized == expected:
                action = "approved" if approved_status == 0 else "rejected"
                return {"success": True, "message": f"Guarantorship request {action} successfully"}
            success = normalized.startswith(("success", "approval recorded.", "rejection recorded."))
            return {"success": success, "message": message}
        
        # Debug the result structure
        print(f"SOAP Result: {result}")
        print(f"Result type: {type(result)}")
        
        # Check if the result is successful
        if hasattr(result, 'return_value'):
            if result.return_value is True:
                action = "approved" if approved_status == 0 else "rejected"
                return {
                    "success": True,
                    "message": f"Guarantorship request {action} successfully"
                }
            else:
                action = "approve" if approved_status == 0 else "reject"
                return {
                    "success": False,
                    "message": f"Failed to {action} guarantorship request"
                }
        # If result is a simple boolean
        elif isinstance(result, bool):
            if result:
                action = "approved" if approved_status == 0 else "rejected"
                return {
                    "success": True,
                    "message": f"Guarantorship request {action} successfully"
                }
            else:
                action = "approve" if approved_status == 0 else "reject"
                return {
                    "success": False,
                    "message": f"Failed to {action} guarantorship request"
                }
        # If result is a tuple or dict
        else:
            action = "approved" if approved_status == 0 else "rejected"
            return {
                "success": True,
                "message": f"Guarantorship request {action} successfully"
            }

    except Exception as e:
        import traceback
        error_msg = str(e)
        print(f"SOAP Error: {error_msg}")
        print(traceback.format_exc())
        return {"error": f"Failed to process guarantorship: {error_msg}"}
    
import logging

logging.basicConfig(level=logging.INFO)

def submit_loan(member_number, loan_number):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.SubmitLoan(
            memberNumber=member_number,
            loanNumber=loan_number
        )

        # Convert Zeep object to Python dict (if applicable)
        response_data = serialize_object(result)

        logging.info("SubmitLoan Response: %s", response_data)
        print("SubmitLoan Response:", response_data)

        return {
            "message": "Loan submitted successfully",
            "data": response_data
        }

    except Exception as e:
        logging.exception("SubmitLoan failed")
        return {"error": str(e)}
    




def get_applied_loans(member_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnOnlineLoans(memberNumber=member_no)

        if not result:
            return {"error": "No response returned from fnOnlineLoans"}

        parsed_result = json.loads(result)

        if parsed_result.get("StatusCode") != "200":
            return {"error": "Failed to fetch loans", "details": parsed_result.get("StatusDescription")}

        return parsed_result.get("OnlineLoans", [])

    except json.JSONDecodeError:
        return {"error": "Invalid JSON returned from fnOnlineLoans"}
    except Exception as e:
        return {"error": str(e)}





def get_loan_details(member_no, loan_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnOnlineLoan(
            memberNumber=member_no,  
            loanNumber=loan_no       
        )

        print("Raw fnOnlineLoan result:", result)

        if not result:
            return {"error": "No data returned from fnOnlineLoan"}

        loan_detail = json.loads(result)

        if not loan_detail.get("LoanNo"):
            return {"error": "Loan details not found."}

        return loan_detail

    except json.JSONDecodeError:
        return {"error": "Invalid JSON returned from fnOnlineLoan"}
    except Exception as e:
        return {"error": str(e)}



def delete_loan_application(member_number, loan_number):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.deleteLoanApplication(
            memberNumber=member_number,
            loanNumber=loan_number
        )

        return {"deleted": result}

    except Exception as e:
        return {"error": str(e)}



def get_loans_for_guarantee(member):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.FnGetLoansForGuarantee(member=member)

        if isinstance(result, dict):
            return result

        result = result.strip()
        if result:
            return json.loads(result)
        else:
            return {"error": "Empty response from SOAP service"}

    except json.JSONDecodeError as json_err:
        return {"error": f"JSON decode error: {str(json_err)}"}
    except Exception as e:
        return {"error": str(e)}


def remove_guarantor(member_number, loan_number, guarantor_number):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.removeGuarantorRequest(
            memberNumber=member_number,
            loanNumber=loan_number,
            guarantorNumber=guarantor_number
        )

        return {"message": "Guarantor removed successfully"}

    except Exception as e:
        return {"error": str(e)}


def get_monthly_deduction_details(member_number):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.FnGetMonthlyDeductionDetails(memberNo=member_number)
        raw_text = getattr(result, "return_value", str(result))

        # Convert literal “\n” sequences into real newlines
        raw_text = raw_text.replace('\\n', '\n')
        # Normalize CRLF to LF
        raw_text = raw_text.replace('\r\n', '\n').strip()

        # ─── Build response skeleton ─────────────────────────────
        response = {
            "member": None,
            "name": None,
            "date": None,
            "contributions": {
                "monthlyContribution": None
            },
            "loanDeductions": [],
            "summary": {}
        }

        # ─── 1) MEMBER / NAME / DATE ───────────────────────────
        m = re.search(
            r"MEMBER:\s*(\d+)\nNAME:\s*(.+?)\nDATE:\s*(\d{2}/\d{2}/\d{2})",
            raw_text
        )
        if m:
            response["member"] = m.group(1)
            response["name"]   = m.group(2)
            response["date"]   = m.group(3)

        # ─── 2) CONTRIBUTIONS ──────────────────────────────────
        c = re.search(
            r"CONTRIBUTIONS:\n- Monthly Contribution:\s*([\d,]+\.\d{2})",
            raw_text
        )
        if c:
            response["contributions"]["monthlyContribution"] = c.group(1)

        # ─── 3) LOAN DEDUCTIONS ───────────────────────────────
        block = re.search(r"LOAN DEDUCTIONS:\n(.+?)\n\nSUMMARY:", raw_text, re.DOTALL)
        if block:
            for loan in re.finditer(
                r"- Loan No:\s*(\S+)\s*\n\s*Type:\s*(.+?)\s*\n\s*Monthly Repayment:\s*([\d,]+\.\d{2})",
                block.group(1)
            ):
                # split type and code
                m2 = re.match(r"(.+?)\s*\((.+?)\)", loan.group(2))
                if m2:
                    typ, code = m2.group(1), m2.group(2)
                else:
                    typ, code = loan.group(2).strip(), None

                response["loanDeductions"].append({
                    "loanNumber": loan.group(1),
                    "loanType": typ,
                    "loanCode": code,
                    "monthlyRepayment": loan.group(3)
                })

        # ─── 4) SUMMARY ────────────────────────────────────────
        s = re.search(
            r"SUMMARY:\n=+\nTotal Loan Repayments:\s*([\d,]+\.\d{2})\nTOTAL MONTHLY DEDUCTIONS:\s*([\d,]+\.\d{2})\n\nGenerated:\s*(.+)",
            raw_text
        )
        if s:
            response["summary"] = {
                "totalLoanRepayments":    s.group(1),
                "totalMonthlyDeductions": s.group(2),
                "generatedDate":          s.group(3).strip()
            }

        return {"status": "success", "data": response}

    except Exception as e:
        return {"status": "error", "message": str(e), "data": None}


def get_active_members():
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.FnActiveMembers()
        parsed_result = serialize_object(result)

        # Parse the nested JSON string into a Python dict
        if isinstance(parsed_result, str):
            parsed_result = json.loads(parsed_result)

        return {
            "status": "success",
            "active_members": parsed_result  # Now it's a proper dict
        }

    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }



def update_member_next_of_kin(
    member_number,
    next_of_kin_name,
    next_of_kin_address,
    next_of_kin_is_beneficiary,
    next_of_kin_email,
    next_of_kin_id_number,
    next_of_kin_relationship_type,
    next_of_kin_dob,
    next_of_kin_telephone
):
    expected_id = (next_of_kin_id_number or "").strip()
    if len(expected_id) > 20:
        return {"error": "Next-of-kin ID number cannot exceed 20 characters.", "code": "next_of_kin_validation"}

    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnUpdateMemberNextOfKin(
            memberNumber=member_number,
            nextOfKinName=next_of_kin_name,
            nextOfKinAddress=next_of_kin_address,
            nextOfKinIsBeneficiary=next_of_kin_is_beneficiary,
            nextOfKinEmail=next_of_kin_email,
            nextOfKinIdNumber=expected_id,
            nextOfKinRelationshipType=next_of_kin_relationship_type,
            nextOfKinDOB=next_of_kin_dob,
            nextOfKinTelephone=next_of_kin_telephone
        )

        message = str(getattr(result, "return_value", result) or "").strip()
        if message.casefold() not in {
            "next of kin added successfuly",
            "next of kin updated successfuly",
            "next of kin added successfully",
            "next of kin updated successfully",
        }:
            if message.casefold() == "relationship type is required":
                return {"error": "Relationship type is required.", "code": "next_of_kin_validation"}
            return {"error": "The ERP did not confirm the save.", "code": "next_of_kin_unconfirmed"}

        if expected_id:
            stored = get_next_of_kin(member_number)
            matching_id = any(
                record.get("Name", "").strip().casefold() == (next_of_kin_name or "").strip().casefold()
                and record.get("IDNumber", "").strip().casefold() == expected_id.casefold()
                for record in stored.get("next_of_kin", [])
            )
            if not matching_id:
                return {
                    "error": "The ERP did not confirm the saved next-of-kin ID number.",
                    "code": "next_of_kin_unconfirmed",
                }

        return {"success": True, "message": message}

    except Exception as e:
        return {"error": str(e)}

def update_member_nominee(
    member_number,
    nominee_name,
    nominee_address,
    nominee_is_beneficiary,
    nominee_email,
    nominee_id_number,
    nominee_relationship_type,
    nominee_dob,
    nominee_allocation,
    nominee_guardian,
    nominee_telephone,
    nominee_is_guardian=False,
):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.fnUpdateMemberNominees(
            memberNumber=member_number,
            nomineeName=nominee_name,
            nomineeAddress=nominee_address,
            nomineeIsBeneficiary=bool(nominee_is_beneficiary),
            nomineeEmail=nominee_email,
            nomineeIdNumber=nominee_id_number,
            nomineeRelationshipType=nominee_relationship_type,
            nomineeDOB=nominee_dob,
            nomineeAllocation=float(nominee_allocation),
            nomineeGuardian=nominee_guardian,
            nomineeTelephone=nominee_telephone,
            nomineeIsGuardian=nominee_is_guardian,
        )

        message = str(getattr(result, "return_value", result) or "").strip()
        if message not in {"Nominee added successfuly", "Nominee modified successfuly"}:
            return {"status": "rejected", "message": message or "The ERP did not confirm the save."}
        return {"status": "success", "message": message}
    except TypeError as exc:
        if "unexpected keyword" in str(exc).lower() and "nomineeisguardian" in str(exc).lower():
            return {
                "status": "error",
                "code": "nominee_service_outdated",
                "message": "The ERP service does not support nominee record types yet. Contact support.",
            }
        return {"status": "error", "message": "The ERP could not process this nominee request."}
    except Exception as e:
        return {"status": "error", "message": str(e)}



def get_next_of_kin(member_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=10)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        response = client.service.fnGetNextofkin(memberNumber=member_no)
        raw = (getattr(response, "return_value", response) or "").strip()
        if not raw:
            return {"status": "success", "next_of_kin": []}

        if raw.startswith("["):
            kin_list = json.loads(raw)
        else:
            # Older ERP versions return name, relationship, email, and telephone.
            kin_list = []
            for match in re.finditer(r"(.*?):::(.*?):::(.*?):::(.*?)::::", raw):
                name, relationship, email, telephone = (field.strip() for field in match.groups())
                kin_list.append({
                    "Name": name,
                    "Relationship": relationship,
                    "Email": email,
                    "Telephone": telephone,
                })

        return {"status": "success", "next_of_kin": kin_list}

    except Exception as e:
        return {"status": "error", "message": str(e), "next_of_kin": []}



def get_member_nominees(member_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        response = client.service.FnGetNOKProfile(memberNo=member_no)

        raw = (getattr(response, "return_value", response) or "").strip()
        if not raw:
            return {"status": "success", "nominees": []}
        if raw.startswith("["):
            return {"status": "success", "nominees": json.loads(raw)}

        # 1) Split entries by double-colon delimiter "::"
        entries = [e for e in raw.split("::") if e.strip()]

        nominees = []
        for entry in entries:
            # 2) Split fields by single-colon ":"
            parts = [p.strip() for p in entry.split(":")]

            nominee = {
                "Name": parts[0]    if len(parts) > 0 else "",
                "DOB": parts[1]     if len(parts) > 1 else "",
                "Allocation": parts[2] if len(parts) > 2 else "",
                "Relationship": parts[3] if len(parts) > 3 else "",
                "Guardian": parts[4]   if len(parts) > 4 else "",
            }
            nominees.append(nominee)

        return {"status": "success", "nominees": nominees}

    except Exception as e:
        return {"status": "error", "message": str(e), "nominees": []}



def get_member_blacklist_status(bosa_no):
    session = Session()
    if USERNAME and PASSWORD:
        session.auth = HTTPBasicAuth(USERNAME, PASSWORD)

    transport = Transport(session=session, timeout=30)
    settings = Settings(strict=False, xml_huge_tree=True)
    client = Client(wsdl=WSDL_URL, transport=transport, settings=settings)

    try:
        result = client.service.GetMemberBlacklistStatus(bosaNo=bosa_no)
        raw_result = str(result).strip()

        if not raw_result:
            return {"error": "No blacklist status returned"}

        # Parse the semicolon-separated result into a dict
        parsed_data = {}
        for item in raw_result.split(';'):
            if ':' in item:
                key, value = item.split(':', 1)
                parsed_data[key.strip()] = value.strip()

        return parsed_data

    except Exception as e:
        return {"error": f"Failed to fetch blacklist status: {str(e)}"}
