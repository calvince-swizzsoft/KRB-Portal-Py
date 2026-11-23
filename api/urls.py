from django.urls import path
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView

from .views import MemberAccountStatisticsView
from .views import RegisterMemberView
from .views import SendOTPView
from .views import ConfirmOTPView
from .views import ChangePasswordView
from .views import MemberProfileView
from .views import MemberAccountDetailsView
from .views import LoanGuarantorsReportView
from .views import LoanGuaranteedReportView
from .views import MemberRunningLoansView
from .views import MemberDetailedReportView
from .views import MemberDepositReportView
from .views import LoanStatementReportView
from .views import LoanProductsView
from .views import ApplyLoanView
from .views import OnlineLoansView
from .views import RequestGuarantorshipView, SelfGuaranteeEligibilityView
from .views import EditOnlineLoanView
from .views import GetLoanGuarantorsView
from .views import MemberLoginView
from .views import MemberShareCertificateView
from .views import ApproveGuarantorshipView
from .views import SubmitLoanView
from .views import AppliedLoansView
from .views import LoanDetailsView
from .views import DeleteLoanApplicationView
from .views import LoansForGuaranteeView
from .views import RemoveGuarantorView
from .views import MonthlyDeductionDetailsView
from .views import EditMemberDetailsView
from .views import ActiveMembersView
from .views import UpdateNextOfKinView
from .views import UpdateNomineeView
from .views import MemberBlacklistStatusView
from .views import GetMemberExistingLoansView
from .views import OnlineLoanRefinancingView



urlpatterns = [
    path('token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    path('member-account-statistics/', MemberAccountStatisticsView.as_view(), name='member-account-statistics'),
    path('register-member/', RegisterMemberView.as_view(), name='register-member'),
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    path('confirm-otp/', ConfirmOTPView.as_view(), name='confirm-otp'),
    path('login-member/', MemberLoginView.as_view(), name='login-member'),
    path('change-password/', ChangePasswordView.as_view(), name='change-password'),

    path('member-profile/', MemberProfileView.as_view(), name='member-profile'),
    path('edit-member-details/', EditMemberDetailsView.as_view(), name='edit-member-details'),
    path('member-account-details/', MemberAccountDetailsView.as_view(), name='member-account-details'),

    path('loan-guaranteed-report/', LoanGuarantorsReportView.as_view(), name='loan-guarantors-report'),
    path('loan-guarantors-report/', LoanGuaranteedReportView.as_view(), name='loan-guaranteed-report'),

    path('member-running-loans/', MemberRunningLoansView.as_view(), name='member-running-loans'),
    path('member-detailed-report/', MemberDetailedReportView.as_view(), name='member-detailed-report'),
    path('member-deposit-report/', MemberDepositReportView.as_view(), name='member-deposit-report'),
    path('loan-statement-report/', LoanStatementReportView.as_view(), name='loan-statement-report'),
    path('member-share-certificate/', MemberShareCertificateView.as_view(), name='member-share-certificate'),

    path('loan-products/', LoanProductsView.as_view(), name='loan-products'),
    path('apply-loan/', ApplyLoanView.as_view(), name='apply-loan'),
    path('online-loans/', OnlineLoansView.as_view(), name='online-loans'),
    path('edit-loan/', EditOnlineLoanView.as_view(), name='edit-loan'),

    path('self-guarantee-eligibility/', SelfGuaranteeEligibilityView.as_view(), name='self-guarantee-eligibility'),
    path('request-guarantorship/', RequestGuarantorshipView.as_view(), name='request-guarantorship'),
    path('approve-guarantorship/', ApproveGuarantorshipView.as_view(), name='approve-guarantorship'),
    path('get-loan-guarantors/', GetLoanGuarantorsView.as_view(), name='get-loan-guarantors'),

    path('submit-loan/', SubmitLoanView.as_view(), name='submit-loan'),
    path('applied-loans/', AppliedLoansView.as_view(), name='applied-loans'),
    path('loan-details/', LoanDetailsView.as_view(), name='loan-details'),
    path('delete-loan/', DeleteLoanApplicationView.as_view(), name='delete-loan'),

    path('loans-for-guarantee/', LoansForGuaranteeView.as_view(), name='loans-for-guarantee'),
    path('remove-guarantor/', RemoveGuarantorView.as_view(), name='remove-guarantor'),

    path('monthly-deductions/', MonthlyDeductionDetailsView.as_view(), name='monthly-deductions'),
    path('active-members/', ActiveMembersView.as_view(), name='active-members'),

    path('update-next-of-kin/', UpdateNextOfKinView.as_view(), name='update_next_of_kin'),
    path('update-nominee/', UpdateNomineeView.as_view(), name='update-nominee'),

    path('member-blacklist-status/', MemberBlacklistStatusView.as_view(), name='member-blacklist-status'),

    path('existing-loans/', GetMemberExistingLoansView.as_view(), name='existing-loans'),
    path('apply-loan-refinancing/', OnlineLoanRefinancingView.as_view(), name='apply-loan-refinancing'),
]
