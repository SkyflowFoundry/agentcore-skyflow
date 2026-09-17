import './amplify-config';
import '@aws-amplify/ui-react/styles.css';
import '@cloudscape-design/global-styles/index.css';
import './App.css';

import { Authenticator } from '@aws-amplify/ui-react';
import { TopNavigation } from '@cloudscape-design/components';
import ChatComponent from './ChatComponent';

// Self sign-up is disabled: users are created in Cognito by an admin. The
// Authenticator renders the whole login flow (sign in, password reset, and MFA
// if it is turned on later) and only renders children once the user is signed in.
export default function App() {
  return (
    <Authenticator hideSignUp>
      {({ signOut, user }) => {
        const label = user?.signInDetails?.loginId ?? user?.username ?? 'Account';
        return (
          <div className="app-shell">
            <TopNavigation
              identity={{ href: '#', title: 'AgentCore + Skyflow' }}
              utilities={[
                {
                  type: 'menu-dropdown',
                  text: label,
                  iconName: 'user-profile',
                  items: [{ id: 'signout', text: 'Sign out' }],
                  onItemClick: ({ detail }) => {
                    if (detail.id === 'signout') signOut();
                  },
                },
              ]}
            />
            <ChatComponent user={user} />
          </div>
        );
      }}
    </Authenticator>
  );
}
