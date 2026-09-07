import React, { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from './ui/select';

type LLMProvider = 'mock' | 'groq' | 'gemini' | 'ollama';

const LLMConfigurator: React.FC = () => {
  const [provider, setProvider] = useState<LLMProvider>('mock');
  const [apiKey, setApiKey] = useState('');
  const [ollamaUrl, setOllamaUrl] = useState('http://localhost:11434');

  const handleSave = () => {
    // In a real application, this would save the configuration securely.
    console.log(`Saving configuration for ${provider}`);
    if (provider === 'ollama') {
        console.log(`Ollama URL: ${ollamaUrl}`);
    } else if (provider !== 'mock') {
        console.log(`API Key: ${apiKey.substring(0, 4)}...`);
    }
    alert('Configuration saved! (Check console)');
  };

  return (
    <Card className="bg-gray-800 border-gray-700 text-gray-200">
      <CardHeader>
        <CardTitle className="text-cyan-400">LLM Backend Configuration</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <Label htmlFor="provider">LLM Provider</Label>
          <Select onValueChange={(value: LLMProvider) => setProvider(value)} defaultValue={provider}>
            <SelectTrigger id="provider" className="bg-gray-700 border-gray-600">
              <SelectValue placeholder="Select a provider" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="mock">Mock (Simulated Data)</SelectItem>
              <SelectItem value="groq">Groq</SelectItem>
              <SelectItem value="gemini">Google Gemini</SelectItem>
              <SelectItem value="ollama">Ollama (Local)</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {provider === 'groq' || provider === 'gemini' ? (
          <div>
            <Label htmlFor="api-key">API Key</Label>
            <Input
              id="api-key"
              type="password"
              placeholder="Enter your API key"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              className="bg-gray-700 border-gray-600"
            />
          </div>
        ) : null}

        {provider === 'ollama' ? (
            <div>
                <Label htmlFor="ollama-url">Ollama URL</Label>
                <Input
                id="ollama-url"
                type="text"
                placeholder="http://localhost:11434"
                value={ollamaUrl}
                onChange={(e) => setOllamaUrl(e.target.value)}
                className="bg-gray-700 border-gray-600"
                />
            </div>
        ) : null}

        <Button onClick={handleSave} className="bg-emerald-500 hover:bg-emerald-600">
          Save Configuration
        </Button>
      </CardContent>
    </Card>
  );
};

export default LLMConfigurator;
