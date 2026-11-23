from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import HttpResponse
from .soap_client import get_member_account_statistics
from .soap_client import register_member
from .soap_client import send_otp
from .soap_client import confirm_otp
from .soap_client import login_member
from .soap_client import change_password
from .soap_client import get_member_profile
from .soap_client import get_member_account_details
from .soap_client import get_loan_guarantors_pdf
from .soap_client import get_loan_guaranteed_pdf
from .soap_client import get_running_loans
from .soap_client import get_member_detailed_statement_pdf
from .soap_client import get_member_deposit_statement_pdf
from .soap_client import get_loan_statement_pdf
from .soap_client import get_loan_products_with_details
from .soap_client import apply_for_loan
from .soap_client import get_online_applied_loans
from decimal import Decimal, InvalidOperation
from .soap_client import guarantorship_policy, request_guarantorship
from .soap_client import edit_online_loan
from .soap_client import get_loan_guarantors
from .soap_client import get_member_sharecertificate_pdf
from .soap_client import approve_guarantorship
from .soap_client import submit_loan
from .soap_client import get_applied_loans
from .soap_client import get_loan_details
from .soap_client import delete_loan_application
from .soap_client import get_loans_for_guarantee
from .soap_client import remove_guarantor
from .soap_client import get_monthly_deduction_details
from .soap_client import edit_member_details
from .soap_client import get_active_members
from .soap_client import update_member_next_of_kin
from .soap_client import update_member_nominee
from .soap_client import get_member_blacklist_status
from rest_framework.permissions import IsAuthenticated
from typing import Any
import logging
from base64 import b64decode
from binascii import Error as Base64Error
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from .soap_client import get_member_existing_loans
from .soap_client import apply_loan_refinancing






class MemberAccountStatisticsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request) -> Response:
        member_no = request.query_params.get("member_no")

        if not member_no:
            return Response(
                {"error": "member_no is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            result = get_member_account_statistics(member_no)
        except Exception as e:
            logger.exception(f"Failed to get statistics for member_no={member_no}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        if "error" in result:
            return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(result, status=status.HTTP_200_OK)


class RegisterMemberView(APIView):
    def post(self, request):
        member_no = request.data.get("member_no")
        id_no = request.data.get("id_no")

        if not member_no or not id_no:
            return Response({"error": "member_no and id_no are required"}, status=status.HTTP_400_BAD_REQUEST)

        data = register_member(member_no, id_no)

        if 'error' in data:
            return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(data, status=status.HTTP_200_OK)


class SendOTPView(APIView):
    def post(self, request):
        member_number = request.data.get("memberNumber")

        if not member_number:
            return Response({"error": "Member number is required"}, status=status.HTTP_400_BAD_REQUEST)

        result = send_otp(member_number)

        if "error" in result:
            return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(result, status=status.HTTP_200_OK)


class ConfirmOTPView(APIView):
    def post(self, request):
        member_number = request.data.get("memberNumber")
        otp_code = request.data.get("otpCode")

        if not member_number or not otp_code:
            return Response(
                {"error": "memberNumber and otpCode are required"}, 
                status=status.HTTP_400_BAD_REQUEST
            )

        result = confirm_otp(member_number, otp_code)

        if result["status"] == "error":
            
            return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        elif result["status"] == "fail":
            
            return Response(result, status=status.HTTP_401_UNAUTHORIZED)

        
        return Response(result, status=status.HTTP_200_OK)



logger = logging.getLogger(__name__)
class MemberLoginView(APIView):
    def post(self, request):
        username = request.data.get("username")
        password = request.data.get("password")

        logger.info(f"Attempting login for username: {username}")

        if not username or not password:
            logger.warning("Username or password missing")
            return Response({"error": "username and password are required."}, status=status.HTTP_400_BAD_REQUEST)

        result = login_member(username, password)

        logger.info(f"SOAP login result: {result}")

        if "error" in result:
            logger.error(f"Login failed at SOAP level: {result['error']}")
            return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        if result.get("authenticated"):
            try:
                logger.info("SOAP authentication successful, trying to get or create Django user...")

                user, created = User.objects.get_or_create(username=username)

                if created:
                    logger.info("User was created. Setting unusable password.")
                    user.set_unusable_password()
                    user.save()

                logger.info("Generating JWT token...")
                refresh = RefreshToken.for_user(user)

                logger.info("Token generated successfully.")

                return Response({
                    "access": str(refresh.access_token),
                    "refresh": str(refresh),
                    "message": "Login successful"
                }, status=status.HTTP_200_OK)

            except Exception as e:
                logger.exception("Token generation failed.")
                return Response({
                    "error": "Failed to generate token.",
                    "detail": str(e)
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        logger.warning("SOAP login failed: Invalid credentials")
        return Response({"message": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)



        

class ChangePasswordView(APIView):
    def post(self, request):
        member_no = request.data.get("member_no")
        current_pass = request.data.get("current_pass")
        new_pass = request.data.get("new_pass")

        if not member_no or not current_pass or not new_pass:
            return Response({"error": "member_no, current_pass, and new_pass are required"}, status=status.HTTP_400_BAD_REQUEST)

        data = change_password(member_no, current_pass, new_pass)

        if 'error' in data:
            return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(data, status=status.HTTP_200_OK)


class MemberProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        member_no = request.query_params.get("member_no")
        if not member_no:
            return Response(
                {"error": "member_no is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if member_no.strip().casefold() != request.user.get_username().strip().casefold():
            return Response({"error": "Access denied."}, status=status.HTTP_403_FORBIDDEN)

        result = get_member_profile(request.user.get_username())

        if result.get("status") != "success":
            return Response(
                {"status": "error", "message": result.get("message")},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        return Response({
            "status":       "success",
            "profile":      result["profile"],
            "next_of_kin":  result.get("next_of_kin", []),
            "nominees":     result.get("nominees", [])
        }, status=status.HTTP_200_OK, headers={"Cache-Control": "private, no-store"})



logger = logging.getLogger(__name__)

MAX_PROFILE_IMAGE_BYTES = 5_000_000
MAX_PROFILE_IMAGE_BASE64_LENGTH = ((MAX_PROFILE_IMAGE_BYTES + 2) // 3) * 4


class EditMemberDetailsView(APIView):

    def post(self, request):
        try:
            data = request.data

            member_number = data.get("memberNumber")
            full_names = data.get("fullNames")
            phone_number = data.get("phoneNumber")
            email = data.get("email")
            id_number = data.get("iDNumber")
            kra_pin = data.get("kRAPin")
            image_blob = data.get("imageBlob")
            kra_pin_doc_pic = data.get("kRAPinDocumentPic")
            id_front = data.get("idFront")
            id_back = data.get("idBack")

            if not member_number:
                logger.warning("memberNumber is missing in request")
                return Response({"error": "memberNumber is required."}, status=400)

            images = {
                "imageBlob": image_blob,
                "kRAPinDocumentPic": kra_pin_doc_pic,
                "idFront": id_front,
                "idBack": id_back,
            }
            for field, image in images.items():
                if image is None or image == "":
                    continue
                if not isinstance(image, str):
                    return Response({"error": f"{field} must be Base64 text."}, status=400)
                too_large = {"error": f"{field} exceeds the 5 MB image limit."}
                if len(image) > MAX_PROFILE_IMAGE_BASE64_LENGTH:
                    return Response(too_large, status=413)
                try:
                    image_size = len(b64decode(image, validate=True))
                except (Base64Error, ValueError):
                    return Response({"error": f"{field} contains invalid Base64."}, status=400)
                if image_size > MAX_PROFILE_IMAGE_BYTES:
                    return Response(too_large, status=413)

            result = edit_member_details(
                member_number=member_number,
                full_names=full_names,
                phone_number=phone_number,
                email=email,
                id_number=id_number,
                kra_pin=kra_pin,
                image_blob=image_blob,
                kra_pin_doc_pic=kra_pin_doc_pic,
                id_front=id_front,
                id_back=id_back
            )

            if "error" in result:
                logger.error("Error in edit_member_details: %s", result["error"])
                return Response(result, status=500)

            logger.info("Member details updated successfully for memberNumber: %s", member_number)
            return Response(result, status=200)

        except Exception as e:
            logger.exception("Unhandled exception in EditMemberDetailsView")
            return Response({"error": str(e)}, status=500)





class MemberAccountDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get("member_no")
        if not member_no:
            return Response({"error": "member_no is required"}, status=status.HTTP_400_BAD_REQUEST)

        details = get_member_account_details(member_no)
        if "error" in details:
            return Response(details, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(details)

class LoanGuarantorsReportView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get('member_no')
        filter_text = request.query_params.get('filter', '')
        big_text = request.query_params.get('big_text', '')

        if not member_no:
            return Response({"error": "member_no is required"}, status=status.HTTP_400_BAD_REQUEST)

        pdf_data = get_loan_guarantors_pdf(member_no, filter_text, big_text)

        if isinstance(pdf_data, dict) and "error" in pdf_data:
            return Response(pdf_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = HttpResponse(pdf_data, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="loan_guaranteed_{member_no}.pdf"'
        return response
    

class LoanGuaranteedReportView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get('member_no')
        filter_text = request.query_params.get('filter', '')
        big_text = request.query_params.get('big_text', '')

        if not member_no:
            return Response({"error": "member_no is required"}, status=status.HTTP_400_BAD_REQUEST)

        pdf_data = get_loan_guaranteed_pdf(member_no, filter_text, big_text)

        if isinstance(pdf_data, dict) and "error" in pdf_data:
            return Response(pdf_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = HttpResponse(pdf_data, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="loan_guaranteed_{member_no}.pdf"'
        return response
    

class MemberRunningLoansView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get("member_no")
        if not member_no:
            return Response({"error": "member_no is required"}, status=status.HTTP_400_BAD_REQUEST)

        loans = get_running_loans(member_no)
        if isinstance(loans, dict) and "error" in loans:
            return Response(loans, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(loans)


class MemberDetailedReportView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get('member_no')
        filter_text = request.query_params.get('filter', '')

        if not member_no:
            return Response({"error": "member_no is required"}, status=status.HTTP_400_BAD_REQUEST)

        pdf_data = get_member_detailed_statement_pdf(member_no, filter_text)

        if isinstance(pdf_data, dict) and "error" in pdf_data:
            return Response(pdf_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return HttpResponse(pdf_data, content_type='application/pdf')




class MemberDepositReportView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get('member_no')
        filter_text = request.query_params.get('filter', '')

        if not member_no:
            return Response({"error": "member_no is required"}, status=status.HTTP_400_BAD_REQUEST)

        pdf_data = get_member_deposit_statement_pdf(member_no, filter_text)

        if isinstance(pdf_data, dict) and "error" in pdf_data:
            return Response(pdf_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return HttpResponse(pdf_data, content_type='application/pdf')


class LoanStatementReportView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get('member_no')
        filter_text = request.query_params.get('filter', '')
        big_text = request.query_params.get('big_text', '')

        if not member_no:
            return Response({"error": "member_no is required"}, status=status.HTTP_400_BAD_REQUEST)

        pdf_data = get_loan_statement_pdf(member_no, filter_text, big_text)

        if isinstance(pdf_data, dict) and "error" in pdf_data:
            return Response(pdf_data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        response = HttpResponse(pdf_data, content_type='application/pdf')
        response['Content-Disposition'] = f'attachment; filename="loan_statement_{member_no}.pdf"'
        return response


class LoanProductsView(APIView):
    #permission_classes = [IsAuthenticated]
    def get(self, request):
        data = get_loan_products_with_details()

        if isinstance(data, dict) and "error" in data:
            return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(data, status=status.HTTP_200_OK)
    
class ApplyLoanView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        member_no = request.user.get_username()
        supplied_member_no = data.get("bosa_no")
        if not isinstance(supplied_member_no, str) or not supplied_member_no.strip():
            return Response({"error": "bosa_no is required"}, status=400)
        if supplied_member_no.strip().casefold() != member_no.strip().casefold():
            return Response({"error": "Access denied."}, status=403)
        
        print(f"\n{'='*80}")
        print("🚀 RECEIVED LOAN APPLICATION REQUEST")
        print(f"{'='*80}")
        print("Request Data:")
        for key, value in data.items():
            if key != "refinance_loans":
                print(f"  {key}: {value}")
        
        refinance_loans = data.get("refinance_loans", [])
        if refinance_loans:
            print(f"\nRefinance Loans Selected: {len(refinance_loans)}")
            for i, loan in enumerate(refinance_loans):
                print(f"  Loan {i+1}: {loan}")

        # Define required fields - ALL modes require these
        required_fields = [
            "bosa_no", "loan_type", "loan_amount", "loan_purpose",
            "repayment_period", "disbursement_mode", "recovery_mode"
        ]
        
        # Check disbursement mode to determine additional requirements
        disbursement_mode = data.get("disbursement_mode")
        
        # Convert to integer for comparison
        try:
            disbursement_mode_int = int(disbursement_mode)
        except (ValueError, TypeError):
            error_msg = "disbursement_mode must be a valid number"
            print(f"\n❌ VALIDATION FAILED: {error_msg}")
            return Response({"error": error_msg}, status=400)
        
        # Check for basic required fields
        for field in required_fields:
            if not data.get(field):
                error_msg = f"{field} is required"
                print(f"\n❌ VALIDATION FAILED: {error_msg}")
                return Response({"error": error_msg}, status=400)
        
        # Validate based on disbursement mode
        if disbursement_mode_int == 4:  # Bank Transfer
            # For Bank Transfer, both account number and bank selection are required
            if not data.get("account_or_mpesa_no"):
                error_msg = "account_or_mpesa_no is required for Bank Transfer"
                print(f"\n❌ VALIDATION FAILED: {error_msg}")
                return Response({"error": error_msg}, status=400)
            
            if not data.get("member_bank"):
                error_msg = "member_bank is required for Bank Transfer"
                print(f"\n❌ VALIDATION FAILED: {error_msg}")
                return Response({"error": error_msg}, status=400)
                
        elif disbursement_mode_int == 8:  # Mobile Money
            # For Mobile Money, only mobile number is required
            if not data.get("account_or_mpesa_no"):
                error_msg = "account_or_mpesa_no is required for Mobile Money"
                print(f"\n❌ VALIDATION FAILED: {error_msg}")
                return Response({"error": error_msg}, status=400)
            
            # Mobile Money doesn't require member_bank, but we need to ensure it's set to 0
            if not data.get("member_bank"):
                data["member_bank"] = 0
                
        elif disbursement_mode_int == 2:  # Cash
            # For Cash, neither account number nor bank is required
            # But we need to ensure they're set to empty/default values
            if not data.get("account_or_mpesa_no"):
                data["account_or_mpesa_no"] = ""
            
            if not data.get("member_bank"):
                data["member_bank"] = 0
        else:
            error_msg = "Invalid disbursement mode selected"
            print(f"\n❌ VALIDATION FAILED: {error_msg}")
            return Response({"error": error_msg}, status=400)
        
        # Ensure account_or_mpesa_no is always a string (even if empty)
        if data.get("account_or_mpesa_no") is None:
            data["account_or_mpesa_no"] = ""
        
        # Ensure member_bank is always set (default to 0 if not provided)
        if data.get("member_bank") is None:
            data["member_bank"] = 0
        
        application_result = {}
        
        try:
            print(f"\n{'='*80}")
            print("📋 STEP 1: Processing main loan application...")
            print(f"{'='*80}")
            
            # First, submit the main loan application
            application_result = apply_for_loan(
                bosa_no=member_no,
                loan_type=data["loan_type"],
                loan_amount=data["loan_amount"],
                loan_purpose=data["loan_purpose"],
                repayment_period=data["repayment_period"],
                disbursement_mode=data["disbursement_mode"],
                recovery_mode=data["recovery_mode"],
                account_or_mpesa_no=data["account_or_mpesa_no"],
                member_bank=data["member_bank"]
            )
            
            # If loan application failed, return the error immediately
            if application_result.get("status") == "error":
                print(f"\n❌ MAIN LOAN APPLICATION FAILED")
                print(f"Error: {application_result.get('message')}")
                return Response(application_result, status=500)
            
            # Get the success message and loan number
            success_message = application_result.get("message", "")
            loan_no = application_result.get("loan_no")
            
            print(f"\n{'='*80}")
            print("✅ MAIN LOAN APPLICATION SUCCESSFUL!")
            print(f"{'='*80}")
            print(f"Success Message: {success_message}")
            print(f"Loan Number from API: {loan_no}")
            
            # If we have a loan number, use it for refinancing
            # If not, try to extract from success message (for backward compatibility)
            if not loan_no:
                # Check if the entire message is a loan number (e.g., "PLN030")
                if success_message and success_message.isalnum() and len(success_message) <= 20:
                    loan_no = success_message
                    print(f"Using entire message as loan number: {loan_no}")
                else:
                    # Try to extract from formatted message
                    import re
                    loan_no_match = re.search(r'LOAN\s*NUMBER\s*[:=\-]?\s*([A-Z0-9]+)', success_message.upper())
                    if loan_no_match:
                        loan_no = loan_no_match.group(1)
                        print(f"Extracted Loan Number from message: {loan_no}")
            
            # If refinancing loans were selected, process them
            refinancing_results = []
            if refinance_loans and isinstance(refinance_loans, list) and loan_no:
                print(f"\n{'='*80}")
                print("🔄 STEP 2: Processing loan refinancing...")
                print(f"Number of loans to refinance: {len(refinance_loans)}")
                print(f"New Loan Number for refinancing: {loan_no}")
                print(f"{'='*80}")
                
                for i, refinance_loan in enumerate(refinance_loans):
                    if isinstance(refinance_loan, dict):
                        # Get required fields
                        existing_loan_no = refinance_loan.get("loan_no")
                        loan_type_for_refinance = refinance_loan.get("loan_type")
                        arrears_amount = refinance_loan.get("arrears_amount", 0)
                        
                        print(f"\nProcessing refinancing {i+1}/{len(refinance_loans)}:")
                        print(f"  Existing Loan No: {existing_loan_no}")
                        print(f"  Loan Type: {loan_type_for_refinance}")
                        print(f"  Arrears Amount: {arrears_amount}")
                        
                        # Validate required fields
                        if not existing_loan_no or not loan_type_for_refinance:
                            print(f"  ⚠️  SKIPPING: Missing required fields")
                            continue
                            
                        # Try to call refinancing
                        try:
                            print(f"  Calling SOAP API for refinancing...")
                            refinancing_result = apply_loan_refinancing(
                                bosa_no=data["bosa_no"],
                                loan_no=loan_no,  # New loan number
                                loan_top_up_no=existing_loan_no,
                                loan_type=loan_type_for_refinance,
                                amount=arrears_amount
                            )
                            
                            print(f"  Refinancing Result: {refinancing_result.get('status')}")
                            print(f"  Message: {refinancing_result.get('message')}")
                            
                            refinancing_results.append({
                                "existing_loan_no": existing_loan_no,
                                "result": refinancing_result
                            })
                        except Exception as e:
                            error_msg = f"Failed: {str(e)}"
                            print(f"  ❌ ERROR: {error_msg}")
                            refinancing_results.append({
                                "existing_loan_no": existing_loan_no,
                                "result": {"status": "error", "message": error_msg}
                            })
            
            # Prepare final response
            response_data = {
                "status": "success",
                "message": success_message,
                "loan_no": loan_no,
                "refinancing_processed": len(refinance_loans) > 0,
                "refinancing_success_count": len([r for r in refinancing_results if r.get("result", {}).get("status") == "success"])
            }
            
            if refinancing_results:
                response_data["refinancing_results"] = refinancing_results
            
            print(f"\n{'='*80}")
            print("🎯 FINAL RESPONSE PREPARED")
            print(f"{'='*80}")
            print(f"Overall Status: {response_data['status']}")
            print(f"Loan Number: {response_data['loan_no']}")
            print(f"Refinancing Processed: {response_data['refinancing_processed']}")
            print(f"Successful Refinancings: {response_data['refinancing_success_count']}")
            print(f"{'='*80}")
            
            return Response(response_data, status=200)
            
        except Exception as e:
            print(f"\n{'='*80}")
            print("❌ UNEXPECTED ERROR IN LOAN APPLICATION")
            print(f"{'='*80}")
            print(f"Error: {str(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            
            if application_result:
                return Response(application_result, status=500)
            return Response({"status": "error", "message": f"Loan application failed: {str(e)}"}, status=500)

class GetMemberExistingLoansView(APIView):
    # permission_classes = [IsAuthenticated]
    
    def get(self, request):
        bosa_no = request.query_params.get("bosa_no")
        
        if not bosa_no:
            return Response({"error": "bosa_no is required"}, status=400)
        
        result = get_member_existing_loans(bosa_no)
        
        if "error" in result:
            return Response(result, status=500)
        
        return Response(result)
    
    
class OnlineLoanRefinancingView(APIView):
    # permission_classes = [IsAuthenticated]
    
    def post(self, request):
        data = request.data
        
        required_fields = [
            "bosa_no", "loan_no", "loan_top_up_no", 
            "loan_type", "amount"
        ]
        
        for field in required_fields:
            if not data.get(field):
                return Response({"error": f"{field} is required"}, status=400)
        
        try:
            # Validate amount is numeric
            amount = float(data["amount"])
            if amount <= 0:
                return Response({"error": "Amount must be greater than 0"}, status=400)
        except ValueError:
            return Response({"error": "Amount must be a valid number"}, status=400)
        
        result = apply_loan_refinancing(
            bosa_no=data["bosa_no"],
            loan_no=data["loan_no"],
            loan_top_up_no=data["loan_top_up_no"],
            loan_type=data["loan_type"],
            amount=data["amount"]
        )
        
        status_code = 200 if result.get("status") == "success" else 500
        return Response(result, status=status_code)
    

class OnlineLoansView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get("member_no")
        if not member_no:
            return Response({"error": "member_no is required"}, status=400)

        result = get_online_applied_loans(member_no)

        if "error" in result:
            return Response(result, status=500)

        return Response(result)

class EditOnlineLoanView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        required_fields = ["loanNumber", "memberNumber", "amountRequest", "loanType", "repaymentPeriod"]

        missing = [field for field in required_fields if field not in data]
        if missing:
            return Response({"error": f"Missing fields: {', '.join(missing)}"}, status=status.HTTP_400_BAD_REQUEST)

        result = edit_online_loan(
            loan_number=data["loanNumber"],
            member_number=data["memberNumber"],
            amount_request=data["amountRequest"],
            loan_type=data["loanType"],
            repayment_period=data["repaymentPeriod"]
        )

        # ✅ Check both singular and multiple errors
        if "error" in result:
            return Response(result, status=status.HTTP_400_BAD_REQUEST)
        if "errors" in result:
            return Response(result, status=status.HTTP_400_BAD_REQUEST)

        return Response(result, status=status.HTTP_200_OK)



class SelfGuaranteeEligibilityView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        loan_number = request.query_params.get("loan_number")
        if loan_number is not None:
            if not loan_number.strip() or len(loan_number) > 20:
                return Response({"error": "A valid loan number is required."}, status=400)
            try:
                limit = guarantorship_policy(
                    "GetSelfGuaranteeLimit", raw=True,
                    memberNo=request.user.get_username(), loanNumber=loan_number,
                )
            except AttributeError as exc:
                if "GetSelfGuaranteeLimit" not in str(exc):
                    logger.exception("Could not load the self-guarantee limit.")
                    return Response({"error": "Could not load your self-guarantee limit."}, status=502)
                return Response({"error": "Self-guarantee is unavailable until the ERP service is updated."}, status=503)
            except Exception:
                logger.exception("Could not load the self-guarantee limit.")
                return Response({"error": "Could not load your self-guarantee limit."}, status=502)
            if limit < 0:
                return Response({"error": "This loan is unavailable for self-guarantee."}, status=403)
            return Response({"max_amount": str(limit)}, headers={"Cache-Control": "private, no-store"})

        loan_type = request.query_params.get("loan_type", "").strip()
        if not loan_type or len(loan_type) > 30:
            return Response({"error": "A valid loan type is required."}, status=400)
        try:
            allowed = guarantorship_policy("AllowsSelfGuarantee", loanType=loan_type)
        except Exception:
            logger.exception("Could not check self-guarantee eligibility.")
            return Response({"error": "Could not check self-guarantee eligibility."}, status=502)
        return Response({"allowed": allowed})


class RequestGuarantorshipView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        member_number = request.data.get("member_number")
        loan_number = request.data.get("loan_number")

        if not isinstance(member_number, str) or not member_number.strip() or not isinstance(loan_number, str) or not loan_number.strip():
            return Response(
                {"error": "member_number and loan_number are required."},
                status=400
            )

        try:
            owns_loan = guarantorship_policy(
                "CanRequestLoanGuarantor",
                memberNo=request.user.get_username(),
                loanNo=loan_number,
            )
        except Exception:
            logger.exception("Could not verify loan ownership for guarantorship.")
            return Response({"error": "Could not verify loan ownership."}, status=502)
        if not owns_loan:
            return Response({"error": "This loan is unavailable for guarantorship requests."}, status=403)

        self_amount = None
        if "self_guarantee_amount" in request.data:
            if member_number.strip().casefold() != request.user.get_username().strip().casefold():
                return Response({"error": "Only the borrower can commit deposits."}, status=403)
            try:
                self_amount = Decimal(str(request.data["self_guarantee_amount"]))
                if (not self_amount.is_finite() or not 0 < self_amount < 10 ** 15
                        or self_amount.as_tuple().exponent < -2):
                    raise InvalidOperation
            except (InvalidOperation, ValueError):
                return Response({"error": "Enter a positive amount with up to two decimal places."}, status=400)
            member_number = request.user.get_username()

        result = request_guarantorship(member_number, loan_number, self_amount)

        if "error" in result:
            return Response(result, status=500)

        if self_amount is not None and not result.get("success"):
            return Response(result, status=400)
        return Response(result, status=200)



class GetLoanGuarantorsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        loan_no = request.query_params.get("loan_no")
        member_number = request.query_params.get("member_number")

        if not loan_no or not member_number:
            return Response({"error": "loan_no and member_number are required."}, status=400)

        result = get_loan_guarantors(loan_no, member_number)

        if "error" in result:
            return Response(result, status=500)

        return Response(result)


class MemberShareCertificateView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get('member_no')
        
        if not member_no:
            return Response(
                {"error": "member_no is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        result = get_member_sharecertificate_pdf(member_no)
        
        if isinstance(result, dict) and "error" in result:
            return Response(
                result,
                status=status.HTTP_502_BAD_GATEWAY  
            )

        response = HttpResponse(result, content_type='application/pdf')
        response['Content-Disposition'] = (
            f'attachment; filename="share_certificate_{member_no}.pdf"'
        )
        return response


class ApproveGuarantorshipView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        data = request.data
        member_no = data.get("memberNo")
        loan_no = data.get("loanNo")
        approved_status = data.get("approvedStatus")

        # Validate input
        if not all([member_no, loan_no, approved_status is not None]):
            return Response(
                {"error": "memberNo, loanNo, and approvedStatus are required"}, 
                status=400
            )

        # Validate approved_status
        try:
            approved_status_int = int(approved_status)
            if approved_status_int not in [0, 1]:
                return Response(
                    {"error": "approvedStatus must be 0 (reject) or 1 (approve)"}, 
                    status=400
                )
        except ValueError:
            return Response(
                {"error": "approvedStatus must be a number (0 or 1)"}, 
                status=400
            )

        signed_in_member = request.user.get_username()
        if str(member_no).strip().upper() != signed_in_member.strip().upper():
            return Response({"error": "You can only respond to your own guarantorship requests."}, status=403)

        amount = None
        if approved_status_int == 0 and data.get("amount") is not None:
            try:
                amount = Decimal(str(data["amount"]))
                if not amount.is_finite() or amount <= 0 or amount.as_tuple().exponent < -2:
                    raise ValueError
            except (InvalidOperation, ValueError):
                return Response({"error": "Enter a positive amount with up to two decimal places."}, status=400)

        result = approve_guarantorship(signed_in_member, loan_no, approved_status_int, amount)

        if "error" in result:
            return Response(result, status=500)

        return Response(result, status=200)




class SubmitLoanView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        member_number = request.data.get("memberNumber")
        loan_number = request.data.get("loanNumber")

        if not member_number or not loan_number:
            return Response({"error": "memberNumber and loanNumber are required"}, status=400)

        result = submit_loan(member_number, loan_number)

        if "error" in result:
            return Response(result, status=500)

        return Response(result, status=200)




class AppliedLoansView(APIView):
    #permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get('member_no')

        if not member_no:
            return Response({"error": "member_no is required"}, status=status.HTTP_400_BAD_REQUEST)

        loans = get_applied_loans(member_no)

        if isinstance(loans, dict) and "error" in loans:
            return Response(loans, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response({"loans": loans}, status=status.HTTP_200_OK)

class LoanDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_no = request.query_params.get('member_no')
        loan_no = request.query_params.get('loan_no')

        if not member_no or not loan_no:
            return Response(
                {"error": "Both 'member_no' and 'loan_no' are required."},
                status=status.HTTP_400_BAD_REQUEST
            )

        loan_detail = get_loan_details(member_no, loan_no)

        if isinstance(loan_detail, dict) and "error" in loan_detail:
            return Response(loan_detail, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(loan_detail, status=status.HTTP_200_OK)


class DeleteLoanApplicationView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        member_number = request.data.get("memberNumber")
        loan_number = request.data.get("loanNumber")

        if not member_number or not loan_number:
            return Response({"error": "memberNumber and loanNumber are required"}, status=400)

        result = delete_loan_application(member_number, loan_number)

        if "error" in result:
            return Response(result, status=500)

        if not result.get("deleted"):
            return Response({"error": "Loan could not be deleted"}, status=400)

        return Response({"message": "Loan deleted successfully"})



class LoansForGuaranteeView(APIView):
    # permission_classes = [IsAuthenticated]

    def get(self, request):
        member = request.query_params.get('member')

        if not member:
            return Response({"error": "member is required"}, status=status.HTTP_400_BAD_REQUEST)

        result = get_loans_for_guarantee(member)

        if isinstance(result, dict) and "error" in result:
            return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        loans = result.get("OnlineRequests", [])
        count = len(loans)

        return Response({
            "count": count,
            "loans": loans
        }, status=status.HTTP_200_OK)



class RemoveGuarantorView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data
        member_number = data.get("memberNumber")
        loan_number = data.get("loanNumber")
        guarantor_number = data.get("guarantorNumber")

        if not all([member_number, loan_number, guarantor_number]):
            return Response({"error": "memberNumber, loanNumber, and guarantorNumber are required"}, status=400)

        result = remove_guarantor(member_number, loan_number, guarantor_number)

        if "error" in result:
            return Response(result, status=500)

        return Response(result, status=200)        



class MonthlyDeductionDetailsView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        member_number = request.query_params.get("memberNumber")

        if not member_number:
            return Response({"error": "memberNumber is required"}, status=400)

        result = get_monthly_deduction_details(member_number)

        if "error" in result:
            return Response(result, status=500)

        return Response(result, status=200)


class ActiveMembersView(APIView):
    def get(self, request):
        result = get_active_members()

        if result.get("status") == "error":
            return Response(result, status=500)

        return Response(result, status=200)



class UpdateNextOfKinView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data

        member_number = data.get("memberNumber")
        next_of_kin_name = data.get("nextOfKinName")
        next_of_kin_address = data.get("nextOfKinAddress")
        next_of_kin_is_beneficiary = data.get("nextOfKinIsBeneficiary", False)
        next_of_kin_email = data.get("nextOfKinEmail")
        next_of_kin_id_number = data.get("nextOfKinIdNumber")
        next_of_kin_relationship_type = data.get("nextOfKinRelationshipType")
        next_of_kin_dob = data.get("nextOfKinDOB")
        next_of_kin_telephone = data.get("nextOfKinTelephone")

        if not member_number:
            return Response({"error": "memberNumber is required."}, status=400)

        result = update_member_next_of_kin(
            member_number,
            next_of_kin_name,
            next_of_kin_address,
            next_of_kin_is_beneficiary,
            next_of_kin_email,
            next_of_kin_id_number,
            next_of_kin_relationship_type,
            next_of_kin_dob,
            next_of_kin_telephone
        )

        if "error" in result:
            return Response(result, status=500)

        return Response(result, status=200)



class UpdateNomineeView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        data = request.data

        required_fields = [
            'memberNumber', 'nomineeName', 'nomineeAddress', 'nomineeIsBeneficiary',
            'nomineeEmail', 'nomineeIdNumber', 'nomineeRelationshipType',
            'nomineeDOB', 'nomineeAllocation', 'nomineeGuardian', 'nomineeTelephone'
        ]

        missing = [field for field in required_fields if field not in data]
        if missing:
            return Response({"error": f"Missing fields: {', '.join(missing)}"}, status=400)

        if not isinstance(data.get("nomineeIsGuardian", False), bool) or not isinstance(data["nomineeIsBeneficiary"], bool):
            return Response({"message": "Guardian and beneficiary flags must be boolean."}, status=400)

        result = update_member_nominee(
            member_number=data['memberNumber'],
            nominee_name=data['nomineeName'],
            nominee_address=data['nomineeAddress'],
            nominee_is_beneficiary=data['nomineeIsBeneficiary'],
            nominee_email=data['nomineeEmail'],
            nominee_id_number=data['nomineeIdNumber'],
            nominee_relationship_type=data['nomineeRelationshipType'],
            nominee_dob=data['nomineeDOB'],
            nominee_allocation=data['nomineeAllocation'],
            nominee_guardian=data['nomineeGuardian'],
            nominee_telephone=data['nomineeTelephone'],
            nominee_is_guardian=data.get('nomineeIsGuardian', False),
        )

        if result["status"] == "success":
            return Response(result, status=status.HTTP_200_OK)
        if result["status"] == "rejected":
            return Response(result, status=status.HTTP_400_BAD_REQUEST)
        return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class MemberBlacklistStatusView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request) -> Response:
        bosa_no = request.query_params.get("bosa_no")

        if not bosa_no:
            return Response(
                {"error": "bosa_no is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            result = get_member_blacklist_status(bosa_no)
        except Exception as e:
            logger.exception(f"Failed to get blacklist status for bosa_no={bosa_no}")
            return Response(
                {"error": "An unexpected error occurred."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        if "error" in result:
            return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(result, status=status.HTTP_200_OK)
