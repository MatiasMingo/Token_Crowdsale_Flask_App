from bs4 import BeautifulSoup
import requests
import re
try: 
    from googlesearch import search 
except ImportError:  
    print("No module named 'google' found") 
  
# to search 
def get_google_search_hrefs(query):
	dict_urls = {}
	for j in search(query, tld="co.in", num=50, stop=50, pause=2): 
		try:
			dict_urls[j] = obtener_hrefs_url(j)
		except:
			dict_urls[j] = []
	return dict_urls

def get_google_search_content(query):
	dict_urls = {}
	for j in search(query, tld="co.in", num=10, stop=10, pause=2): 
		try:
			dict_urls[j] = obtener_content_url(j)
		except:
			dict_urls[j] = []
	return dict_urls

def obtener_hrefs_url(url):
    page_response = requests.get(url, timeout=5)
    soup = BeautifulSoup(page_response.content, "html.parser")
    textContent = ""
    links = []
    for a in soup.find_all('a', href=True):
    	links.append(a['href'])
    """
    for node in soup.findAll('p'):
        textContent += str(node.findAll(text=True))
    lista_palabras = textContent.strip(",").strip(".").strip("[").strip("]").strip("(").strip(")").split(" ")
    lista_palabras_lower = [palabra.lower() for palabra in lista_palabras]
    """
    return links

def obtener_content_url(url):
    page_response = requests.get(url, timeout=5)
    soup = BeautifulSoup(page_response.content, "html.parser")
    textContent = ""
    links = []
    for node in soup.findAll('p'):
        textContent += str(node.findAll(text=True))
    lista_palabras = textContent.strip(",").strip(".").strip("[").strip("]").strip("(").strip(")").split(" ")
    lista_palabras_lower = [palabra.lower() for palabra in lista_palabras]
    return lista_palabras_lower

def obtener_pegas_programador(query):
	palabras_clave = ["programador"]
	dict_urls = get_google_search_hrefs(query)
	filtered_list = list()
	for url, content in dict_urls.items():
		for link in content:
			details_link = re.split('[^a-zA-Z]', link)
			for palabra in palabras_clave:
				if palabra in details_link:
					filtered_list.append(link)
	with open("programming_jobs.txt", "w") as programming_jobs_file:
		for link in filtered_list:
			programming_jobs_file.write("{} \n \n".format(link))
	"""
	posibilities_dict = {}
	for link in filtered_list:
		try:
			contenido = obtener_content_url(link)
			print(contenido)
		except:
			continue
	print(posibilities_dict)
	"""

def obtener_detalles_terrenos(query):
	palabras_clave = ["terreno", "parcela"]
	dict_urls = get_google_search_hrefs(query)
	filtered_list = list()
	for url, content in dict_urls.items():
		for link in content:
			details_link = re.split('[^a-zA-Z]', link)
			for palabra in palabras_clave:
				if palabra in details_link:
					filtered_list.append(link)
	posibilities_dict = {}
	for link in filtered_list:
		try:
			contenido = obtener_content_url(link)
			index_square_meters = contenido.index('m²')
			index_price = contenido.index('$')
			tamaño = contenido[index_square_meters-1]
			precio = contenido[index_price+1]
			posibilities_dict[link] = {"precio": precio, "tamaño":tamaño}
		except:
			continue
	print(posibilities_dict)

obtener_pegas_programador("se busca programador Santiago Chile")