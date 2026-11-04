from django import forms

class MessageForm(forms.Form):
    text = forms.CharField(
        label="Enter Email Text",
        required=True,
        widget=forms.Textarea(
            attrs={
                "class": "form-control",
                "placeholder": "Paste the email message here...",
                "rows": 8,
            }
        )
    )