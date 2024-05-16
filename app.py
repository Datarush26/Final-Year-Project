from flask import Flask,render_template,url_for,request
import pickle
import nltk
from nltk.corpus import  stopwords
#nltk.download('stopwords')
from nltk.stem.porter import PorterStemmer
import string
import re
from urllib.parse import urlparse
import numpy as np
app=Flask(__name__)

# Home page code
@app.route('/')
def home():
    return render_template('index.html')

#About Page Route
@app.route('/about')
def about():
    return render_template('about.html')

# Code for sms spam detection

sd=pickle.load(open('sms_spam\Vectorizer.pkl','rb'))
model=pickle.load(open('sms_spam\Logistic_regg.pkl' , 'rb'))
ps=PorterStemmer()
def transform(text):
  if text is None:
     return ""
  text=text.lower()
  text=nltk.word_tokenize(text)
  y=[]
  for i in text:
    if i.isalnum():
      y.append(i)
  text=y[:]
  y.clear()
  for i in text:
    if i not in stopwords.words('english') and i not in string.punctuation:
      y.append(i)
  text=y[:]
  y.clear()
  for i in text:
    y.append(ps.stem(i))
  return " ".join(y)

#Spam Sms webpage code

@app.route('/spam',methods=['POST','GET'])
def spam():
    prediction=""
    if request.method == "POST":
      data = request.form.get("text")
      newdata=transform(data)
      vector=sd.transform([newdata])
      b=model.predict(vector)[0]
      if b==1:
         prediction="spam"
         return render_template('spam.html',prediction="{}".format(prediction))
      else:
        prediction= "not spam"
        return render_template('spam.html',prediction="{}".format(prediction))
    else:
      return render_template('spam.html',prediction="{}".format(prediction))

#Use of IP or not in domain
def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)' # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
#Counting of dots 
def count_dot(url):
    count_dot = url.count('.')
    return count_dot
#Counting of www
def count_www(url):
    url.count('www')
    return url.count('www')
#Counting of directory
def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')
#Abnormal url or not
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
# Url shortening used or not
def shortening_service(url):
    match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                      'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                      'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                      'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                      'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                      'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                      'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                      'tr\.im|link\.zip\.net',
                      url)
    if match:
        return 1
    else:
        return 0
#Calculating the url length
def url_length(url):
    return len(str(url))
#Checking the url does have https or not
def count_https(url):
    return url.count('https')
#Checking the url does have http or not
def count_http(url):
    return url.count('http')
def letter_count(url):
    letters = 0
    for i in url:
        if i.isalpha():
            letters = letters + 1
    return letters

def main(url):
    status = []
    
    status.append(having_ip_address(url))
    status.append(abnormal_url(url))
    status.append(count_dot(url))
    status.append(count_www(url))
    status.append(no_of_dir(url))
    status.append(shortening_service(url))
    status.append(count_https(url))
    status.append(count_http(url))
    status.append(url_length(url))
    status.append(letter_count(url))

    return status

#Phising Page Code

urlmodel=pickle.load(open("Phishing_website\Random_forestforPhising.pkl","rb"))
urllabelencode=pickle.load(open("Phishing_website\Labelencoderfor_phising.pkl","rb"))
urlscaling=pickle.load(open("Phishing_website\standardscalerfor_phising.pkl","rb"))
@app.route('/phishing',methods=['POST','GET'])
def phishing():
    prediction=""
    if request.method == "POST":
      data = request.form.get("text")
      data2=main(data)
      data3 = np.array(data2).reshape((1, -1))
      #final_data=urlscaling.transform(data3)
      pred=urlmodel.predict(data3)
      prediction=urllabelencode.classes_[pred[0]]

      return render_template('website.html',prediction="The url can be a {} type of website".format(prediction))
    else:
      return render_template('website.html',prediction=prediction)

# Code for credit card fraud detection

creditcard_model=pickle.load(open("credit_card_fraud\Bankmodel.pkl",'rb'))
creditcard_label=pickle.load(open("credit_card_fraud\encoder.pkl",'rb'))
creditcard_scaling=pickle.load(open("credit_card_fraud\scaling.pkl",'rb'))
@app.route('/creditcard',methods=['POST','GET'])
def creditcard():
    prediction=""
    if request.method == "POST":
        all_inputs = request.form.getlist('text') + request.form.getlist('amount') + request.form.getlist('oldbalance')+request.form.getlist('newbalance')
        all_inputs[0]=creditcard_label.transform([all_inputs[0]])[0]
        for i in range(1,4):
           all_inputs[i]=float(all_inputs[i])
        all_inputs=np.array(all_inputs).reshape((1, -1))
        final_input=creditcard_scaling.transform(all_inputs)
        pred=creditcard_model.predict(final_input)
        if pred==1:
         prediction="Fraud"
         return render_template('banking.html',prediction="{}".format(prediction))
        else:
         prediction= "not Fraud"
         return render_template('banking.html',prediction="{}".format(prediction))
    else:
      return render_template('banking.html',prediction="{}".format(prediction))










if __name__=="__main__":
    app.run(debug=True)