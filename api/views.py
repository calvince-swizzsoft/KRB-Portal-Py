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
from .soap_client import request_guarantorship
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
from rest_framework.permissions import IsAuthenticated
from typing import Any
import logging
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from django.contrib.auth.models import User






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

        result = get_member_profile(member_no)

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
        }, status=status.HTTP_200_OK)



logger = logging.getLogger(__name__)

class EditMemberDetailsView(APIView):

    def post(self, request):
        try:
            data = request.data

            logger.info("Received POST data for edit-member-details: %s", data)

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
    permission_classes = [IsAuthenticated]
    def get(self, request):
        data = get_loan_products_with_details()

        if isinstance(data, dict) and "error" in data:
            return Response(data, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(data, status=status.HTTP_200_OK)
    
class ApplyLoanView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        data = request.data
        bosa_no = data.get("bosa_no")
        loan_type = data.get("loan_type")
        loan_amount = data.get("loan_amount")
        loan_purpose = data.get("loan_purpose")
        repayment_period = data.get("repayment_period")

        if not all([bosa_no, loan_type, loan_amount, loan_purpose, repayment_period]):
            return Response({"status": "error", "message": "All fields are required"}, status=400)

        result = apply_for_loan(bosa_no, loan_type, loan_amount, loan_purpose, repayment_period)

        if result.get("status") == "error":
            return Response(result, status=400)

        return Response(result, status=200)



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



class RequestGuarantorshipView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        member_number = request.data.get("member_number")
        loan_number = request.data.get("loan_number")

        if not member_number or not loan_number:
            return Response({"error": "member_number and loan_number are required."}, status=400)

        result = request_guarantorship(member_number, loan_number)

        if "error" in result:
            return Response(result, status=500)

        return Response(result)


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

        if not all([member_no, loan_no, approved_status in ["0", "1", 0, 1]]):
            return Response({"error": "memberNo, loanNo, and approvedStatus (0 or 1) are required"}, status=400)

        result = approve_guarantorship(member_no, loan_no, approved_status)

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
    #permission_classes = [IsAuthenticated]

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
        )

        if result["status"] == "success":
            return Response(result, status=status.HTTP_200_OK)
        else:
            return Response(result, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
