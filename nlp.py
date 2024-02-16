

"""## 讀取檔案
* 把抓到的commod(result.json)放到google 雲端硬碟的root
* 把[github]((https://github.com/mitre/cti/tree/master/enterprise-attack/x-mitre-tactic)) 的 14個tactic.json 放到google 雲端硬碟root/tactic

讀取 linux commond
"""

import os
import json
import pathlib
import pandas as pd
import re

from google.colab import drive
drive.mount('/content/drive')

dirPath = r"drive/MyDrive/"
f = open(dirPath + 'result.json')
data = json.load(f)

# Use pd.json_normalize to convert the JSON to a DataFrame
commond = pd.json_normalize(data, meta=['command', 'description', 'name', 'section'])

# Rename the columns for clarity
commond.columns = ['command', 'description', 'name', 'section']

# Display the DataFrame
print(commond)
commond = pd.DataFrame(commond)
commond = technique.dropna()
commond.reset_index(drop=True,inplace=True)
commond

"""讀取 tactic"""

dirPath = r"drive/MyDrive/tactic"

tmp = []
for f in os.listdir(dirPath):
  if pathlib.Path(f).suffix == ".json":
    data = json.load(open(os.path.join(dirPath, f)))
    tmp.append([data['objects'][0]['name'], data['objects'][0]['description']])

tatic = pd.DataFrame(tmp)
tatic.columns = ['name', 'description']
print(tatic)

"""## 抓 Technique"""

import pandas as pd
url = "https://attack.mitre.org/techniques/enterprise/"

tables = pd.read_html(url)

len(tables)
technique = tables[0]

technique = technique.rename(columns={"Description": "description", "Name": "name"})
technique = pd.DataFrame(technique)
technique = technique.dropna()
technique.reset_index(drop=True,inplace=True)
technique

"""## Technique map to Tactic"""

import pandas as pd
url = "https://attack.mitre.org/matrices/enterprise/"

tables = pd.read_html(url)

len(tables)
matrix = tables[0]

#matrix = technique.rename(columns={"Description": "description", "Name": "name"})
matrix = pd.DataFrame(matrix)
#matrix = technique.dropna()
#matrix.reset_index(drop=True,inplace=True)
matrix

"""# Step2. Pre-Processing(SnowballStemmer)"""

# Commented out IPython magic to ensure Python compatibility.
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from nltk.stem.porter import PorterStemmer
from nltk.stem.snowball import SnowballStemmer
import numpy as np

pd.options.display.max_columns = 30
# %matplotlib inline

def decontracted(phrase):
    # specific
    phrase = re.sub(r"won\'t", "will not", phrase)
    phrase = re.sub(r"can\'t", "can not", phrase)

    # general
    phrase = re.sub(r"n\'t", " not", phrase)
    phrase = re.sub(r"\'re", " are", phrase)
    phrase = re.sub(r"\'s", " is", phrase)
    phrase = re.sub(r"\'d", " would", phrase)
    phrase = re.sub(r"\'ll", " will", phrase)
    phrase = re.sub(r"\'t", " not", phrase)
    phrase = re.sub(r"\'ve", " have", phrase)
    phrase = re.sub(r"\'m", " am", phrase)
    phrase = re.sub(r"early access review", "early access review ", phrase)
    phrase = re.sub(r"\+", " + ", phrase)
    phrase = re.sub(r"\-", " - ", phrase)
    phrase = re.sub(r"/10", "/10 ", phrase)
    phrase = re.sub(r"10/", " 10/", phrase)
    return phrase

stemmer = SnowballStemmer("english")
def stemming_tokenizer(str_input):
  words = re.sub(r"[^a-zA-Z]{2,}", " ", str_input).lower().split()
  words = [stemmer.stem(word) for word in words]
  return " ".join(words)

def clean_reviews(lst):
    # remove URL links (httpxxx)
    lst = np.vectorize(remove_pattern)(lst, "https?://[A-Za-z0-9./]*")
    # remove special characters, numbers, punctuations (except for #)
    lst = np.core.defchararray.replace(lst, "[^a-zA-Z]", " ")
    # remove amp with and
    lst = np.vectorize(replace_pattern)(lst, "amp", "and")
    # remove hashtags
    lst = np.vectorize(remove_pattern)(lst, "#[A-Za-z0-9]+")
    lst = np.vectorize(remove_pattern)(lst, "#[\w]*")
    return lst
def remove_pattern(input_txt, pattern):
    r = re.findall(pattern, input_txt)
    for i in r:
        input_txt = re.sub(i, '', input_txt)
    return input_txt
def replace_pattern(input_txt, pattern, replace_text):
    r = re.findall(pattern, input_txt)
    for i in r:
        input_txt = re.sub(i, replace_text, input_txt)
    return input_txt

commond.loc[4, 'description']

# Applying pre-processing to user reviews
def preprocessing(df):
  text2 = clean_reviews(list(df['description'].astype('str')))
  text3 = [ta.lower() for ta in text2]
  text4 = [''.join([i if ord(i) < 128 else ' ' for i in t]) for t in text3]
  text5 = [decontracted(u) for u in text4]
  text6 = [stemming_tokenizer(u) for u in text5]
  return text6

commond.loc[4, 'description']

fixedCommond = preprocessing(commond)
#fixedTatic = preprocessing(tatic)
fixedTechnique = preprocessing(technique)

"""# Step3. Mapping(Bag of Word、TF IDF)"""

from sklearn.feature_extraction.text import CountVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.feature_extraction.text import TfidfVectorizer

url = "https://attack.mitre.org/tactics/enterprise/"

tables = pd.read_html(url)

#len(tables)
matrix = tables[0]
matrix
#matrix = matrix.rename(columns={"Description": "description", "Name": "name"})
matrix = pd.DataFrame(matrix)
matrix = matrix.dropna()
matrix.reset_index(drop=True,inplace=True)

dic = {}
for i in range(len(technique)):
  dic[technique.loc[i, 'name']] = []

url = "https://attack.mitre.org/tactics/"
for i in range(len(matrix)):
  tables2 = pd.read_html(url + matrix.loc[i]['ID'] + '/')
  matrix2 = tables2[0]
  matrix2 = pd.DataFrame(matrix2)
  matrix2 = matrix2.dropna()
  matrix2.reset_index(drop=True,inplace=True)
  for j in range(len(matrix2)):
    dic[matrix2.loc[j]['Name']].append(matrix.loc[i]['Name'])

print(dic)
json2 = json.dumps(dic)
print(json2)

f = open("mapTech2Tactic.json", "w+")
f.write(json2)
f.close()

#計算文件與文件的cosine similarity
def similarity(vec):
  mapping = {}
  for i in range(len(fixedTechnique), 2631):
    max = 0;
    max_id = 0;
    for j in range(0, len(fixedTechnique)):
      score = cosine_similarity(vec[i], vec[j])
      if(max < score):
        max = score
        max_id = j
    if commond.loc[i, 'name']:
      name = commond.loc[i, 'name'].split(' ')
    else:
      name = [commond.loc[i, 'name'],0]
    if max != 0:
      print(name[0], ': is mapping to', technique.loc[max_id, 'name'])
      mapping[name[0]] = technique.loc[max_id, 'name']
    else:
      print(name[0], ': is not mapping to any technique')
      mapping[name[0]] = ''
  '''
  with open("sample.json", "w") as outfile:
    json.dumps(mapping, outfile)
  '''
  json2 = json.dumps(mapping)
  print(json2)

  f = open("sample.json", "w+")
  f.write(json2)
  f.close()

"""## Bag of Words"""

count_vect = CountVectorizer(analyzer='word', stop_words = "english")
countdf_user_review = count_vect.fit_transform(fixedTechnique + fixedCommond)
print("All tags are:")
print(count_vect.get_feature_names_out())
print("Matrix looks like")
print(countdf_user_review.shape)
print(countdf_user_review.toarray())

countdf_user_review_df = pd.DataFrame(data = countdf_user_review.toarray())
countdf_user_review_df.columns = count_vect.get_feature_names_out()
countdf_user_review_df.head()

similarity(countdf_user_review)

"""## BoW for N-gram"""

# Count Vectorizer for N-grams
count_vect2 = CountVectorizer(analyzer='word', ngram_range=(2,3), stop_words = "english")
countdf_user_review2= count_vect2.fit_transform(fixedTechnique + fixedCommond)
print("All tags are:")
print(count_vect2.get_feature_names_out())
print("Matrix looks like")
print(countdf_user_review2.shape)
print(countdf_user_review2.toarray())

countdf_user_review_df2 = pd.DataFrame(data = countdf_user_review2.toarray())
countdf_user_review_df2.columns = count_vect2.get_feature_names_out()
countdf_user_review_df2.head()

similarity(countdf_user_review2)

"""## TF-IDF"""

# Word level Tf-Idf
tfidf_vect = TfidfVectorizer(analyzer='word', stop_words = "english")
tfidf_user_review = tfidf_vect.fit_transform(fixedTechnique + fixedCommond)
print("All tags are:")
print(tfidf_vect.get_feature_names_out())
print("Matrix looks like")
print(tfidf_user_review.shape)
print(tfidf_user_review.toarray())

tfidf_user_review_df = pd.DataFrame(data = tfidf_user_review.toarray())
tfidf_user_review_df.columns = tfidf_vect.get_feature_names_out()
tfidf_user_review_df.head()

similarity(tfidf_user_review)

"""## Tf-Idf for N-grams"""

# Tf-Idf for N-grams
tfidf_vect2 = TfidfVectorizer(analyzer='word', ngram_range=(2,3), stop_words = "english")
tfidf_user_review2 = tfidf_vect2.fit_transform(fixedTechnique + fixedCommond)
print("All tags are:")
print(tfidf_vect2.get_feature_names_out())
print("Matrix looks like")
print(tfidf_user_review2.shape)
print(tfidf_user_review2.toarray())

tfidf_user_review_df2 = pd.DataFrame(data = tfidf_user_review2.toarray())
tfidf_user_review_df2.columns = tfidf_vect2.get_feature_names_out()
tfidf_user_review_df2.head()

similarity(tfidf_user_review2)

"""以上皆可跑"""